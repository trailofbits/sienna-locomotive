// XXX_INCLUDE_TOB_COPYRIGHT_HERE

// This is the main triage class that works on a single minidump file (versus triager.cc which handles command line, multiple files, etc.
// It runs the 3 processors (!exploitable, breakpad, and tracer) on the minidump.  The tracer processor is a little special since it can
// have our taint information.  From the processors the highest score is used for the exploitability.  The exploitability and important
// details from the crash and minidump analysis are put in a triage.json file.

#include "triage.h"
#include "common/rc4x.hh"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <numeric>
#include <regex>
#include <string>

#include "Xploitability.h"
#include "XploitabilityBangExploitable.h"
#include "XploitabilityBreakpad.h"
#include "XploitabilityTracer.h"
#include "google_breakpad/processor/minidump.h"
#include "google_breakpad/processor/minidump_processor.h"
#include "google_breakpad/processor/process_state.h"
#include "google_breakpad/processor/call_stack.h"
#include "google_breakpad/processor/stack_frame.h"


using namespace std;
using namespace google_breakpad;

using google_breakpad::MinidumpProcessor;
using google_breakpad::ProcessState;
using google_breakpad::SimpleSymbolSupplier;

namespace sl2 {


////////////////////////////////////////////////////////////////////////////
// Triage()
//
// Constructor for Triage class which loads a minidump file at minidumpPath
////////////////////////////////////////////////////////////////////////////
Triage::Triage( const string& minidumpPath ) 
    :   minidumpPath_(minidumpPath),
        symbolSupplier_(minidumpPath),
        proc_(&symbolSupplier_, &resolver_, true),
        dump_ (minidumpPath) {

}


////////////////////////////////////////////////////////////////////////////
// process()
//      Does actual processing a minidump file, agnostic of exploitability
//  engine
StatusCode Triage::process() {

    ProcessResult   sc;

    // Read in minidump
    if( !dump_.Read() ) {
        cerr << "Unable to read dumpfile." << endl;
        return StatusCode::ERROR;
    }

    // Do some breakpad processing
    sc = proc_.Process( &dump_, &state_);
    if( PROCESS_OK!=sc ) {
        cerr << "Unable to process dumpfile." << endl;
        return StatusCode::ERROR;
    }

    cout << "-----------------------------------------------" << endl;
    cout << minidumpPath_ << endl;

    // Loads up a crash.json file for taint info
    dirPath_ = fs::path(minidumpPath_);
    dirPath_ = dirPath_.parent_path();
    fs::path jsonPath(dirPath_.string());
    jsonPath.append("crash.json");
    
    // There is a bug in Visual Studio that doesn't let you do this the sane way...
    vector< unique_ptr<Xploitability> > engine;
    engine.push_back( make_unique<XploitabilityBreakpad>( &dump_, &state_) );
    engine.push_back( make_unique<XploitabilityBangExploitable>( &dump_, &state_) );    

    for( const auto& mod : engine ) {
        const auto result   = mod->process();
        results_.push_back( result );
    }

    // Tracer is a special engine, since it uses our taint information from tracer.cpp
    // We also need a single Xploitability module to get more minidump information so
    // might as well use this one with a longer scope
    tracer_  = make_unique<XploitabilityTracer>( &dump_, &state_, jsonPath.string());
    const auto result   = tracer_->process();
    results_.push_back( result );

    // Write the final triage information to the triage.json file
    fs::path outminidumpPath(dirPath_.string());
    outminidumpPath.append("triage.json");
    persist(outminidumpPath.string());
    
    // It's all good.
    return StatusCode::GOOD;
}

////////////////////////////////////////////////////////////////////////////
// normalize()
//  Normalizes scores between 0 and 1
double Triage::normalize(double x) {
    x = std::max(0.0,   x);
    x = std::min(1.0,   x);
    return x;
}

////////////////////////////////////////////////////////////////////////////
// signalType()
int Triage::signalType() {
    return 0;
}


////////////////////////////////////////////////////////////////////////////
// callStack()
const vector<uint64_t> Triage::callStack() const {
    int threadid = state_.requesting_thread();
    const CallStack* stack = state_.threads()->at(threadid);

    uint8_t     i = 0;
    
    vector<uint64_t> ret;
    for( StackFrame* frame : *stack->frames()  ) { 
        ret.push_back(frame->ReturnAddress());
    }
    return ret;
}


////////////////////////////////////////////////////////////////////////////
// stackHash()
//      Returns the hash of the callstack.  This should uniquely identifiy
// a crash (even with ASLR) by using the last 3 nibbles of the offset for
// each call in the callstack
const string Triage::stackHash() const {
    uint64_t    stackhash = 0;
    auto calls = callStack();
    sort( calls.begin(), calls.end() );
    auto last  = unique(calls.begin(), calls.end());
    calls.erase(last, calls.end());
    
    RC4x rc4(true);

    for( uint64_t addr : calls ) { 
        // We only want the 12 bits of the offset to ignore aslr
        addr &= 0xFFF;
        rc4.encrypt( (uint8_t*)&addr, (uint8_t*)&stackhash,  (size_t)sizeof(stackhash) );
    }

    ostringstream oss;
    oss << setfill('0') << setw(sizeof(stackhash)/4) << hex << stackhash;    
    return oss.str();
}

////////////////////////////////////////////////////////////////////////////
// triageTag()
//      A tag is basically a string that uniquely identifies the crash.  Its
// includes exploitabilty, crash reason, and eventually a unique address
const string Triage::triageTag() const {
    fs::path  tPath;
    tPath.append( exploitability() );
    tPath.append( crashReason() );
    tPath.append(stackHash());
    string ret =  tPath.generic_string();
    return ret;
}

////////////////////////////////////////////////////////////////////////////
// crashReason()
//      The reason for the crash as far as the exception that caused it.
const string Triage::crashReason()  const {
    string ret;
    regex regexFilter { "[^a-zA-Z0-9_]+" };

    if(  state_.crash_reason().size()>0 ) {
        ret = state_.crash_reason();
    } else {
        ret =  "Unknown";
    }
    // Filter out bad characters in case we want to use the triageTag for a 
    // minidumpPath
    ret = regex_replace( ret, regexFilter, "_" );
    return ret;
}

////////////////////////////////////////////////////////////////////////////
// crashAddress()
//      This is the offending memory address
const uint64_t Triage::crashAddress() const { 
    return state_.crash_address();
}

////////////////////////////////////////////////////////////////////////////
// exploitability()
//      returns value from 0 to 4 for exploitabilty.  0 being None, 4 being
// High
XploitabilityRank Triage::exploitabilityRank() const {    
    XploitabilityRank rank = XploitabilityRank::XPLOITABILITY_NONE;
    for( auto arank : ranks() ) {
        if( arank > rank ) {
            rank = arank;
        }
    }
    return rank;
}

////////////////////////////////////////////////////////////////////////////
// exploitability()
//      String version of exploitabilty from None to High
const string Triage::exploitability() const {
    //return Xploitability::rankToString( exploitabilityRank() );
    XploitabilityRank rank = exploitabilityRank();    
    return ~rank;
}

////////////////////////////////////////////////////////////////////////////
// ranks()
//      Creates a vector of the ranks from the 3 engines
vector<XploitabilityRank>   Triage::ranks() const {
    vector<XploitabilityRank> ret;
    for( auto result : results_ ) {
        ret.push_back(result.rank);
    }
    return ret;
}


////////////////////////////////////////////////////////////////////////////
// ranksString()
//      Each of the 3 engines give a 0-4 rank, so this stringifies them all
const string Triage::ranksString() const {
    ostringstream ss;
    for( auto& rank : ranks() ) {
        ss << rank << " ";
    }
    return ss.str();
}

////////////////////////////////////////////////////////////////////////////
// minidumpPath()
//      Path to the minidump file which was analyzed
const string Triage::minidumpPath() const {
    return minidumpPath_;
}


////////////////////////////////////////////////////////////////////////////
// toJson()
//      Converts a Triage object into a json object for persistence
json Triage::toJson() const {
    return json{
        { "crashReason",        crashReason() },
        { "crashAddress",       crashAddress() },
        { "exploitability",     exploitability() },
        { "tag",                triageTag() },
        { "callStack",          callStack() },
        { "stackHash",          stackHash() },
        { "minidumpPath",       minidumpPath() },
        { "ranks",              ranks() },
        { "rank",               exploitabilityRank() },
        { "instructionPointer", instructionPtr_, },
        { "stackPointer",       stackPtr_, },
        { "tracer",             tracer_->toJson() }
    };
}


////////////////////////////////////////////////////////////////////////////
// persist()
//      Writes a triage object to triage.json
void Triage::persist(const string minidumpPath)  const {
    ofstream ofs(minidumpPath);
    json j = toJson();
    ofs << j << endl;
    ofs.close();
}


////////////////////////////////////////////////////////////////////////////
// <<()
ostream& operator<<(ostream& os, Triage& self) {
    os << "Exploitability: "        << self.exploitability()        << endl;
    os << "Ranks         : "        << self.ranksString()           << endl;
    os << "Crash Reason  : "        << self.crashReason()           << endl;
    os << "Tag           : "        << self.triageTag()            << endl;
    return os;  
}  
  


} // namespace