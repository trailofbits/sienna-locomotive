////////////////////////////////////////////////////////////////////////////
// Trail of Bits
// July 2018
////////////////////////////////////////////////////////////////////////////

#include "triage.h"


#include "google_breakpad/processor/minidump.h"
#include "google_breakpad/processor/minidump_processor.h"
#include "google_breakpad/processor/process_state.h"

#include "Xploitability.h"
#include "XploitabilityBreakpad.h"
#include "XploitabilityBangExploitable.h"
#include "XploitabilityTracer.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <numeric>
#include <regex>
#include <string>


using namespace std;
using namespace google_breakpad;

using google_breakpad::MinidumpProcessor;
using google_breakpad::ProcessState;
using google_breakpad::SimpleSymbolSupplier;

namespace sl2 {

static const double kHighCutoff        = 1.0;
static const double kMediumCutoff      = 0.8;
static const double kLowCutoff         = 0.5;
static const double kInterestingCutoff = 0.25;


////////////////////////////////////////////////////////////////////////////
// Triage()
//
// Constructor for Triage class which loads a minidump file at path
////////////////////////////////////////////////////////////////////////////
Triage::Triage( const string& path ) 
    :   path_(path),
        symbolSupplier_(path),
        proc_(&symbolSupplier_, &resolver_, true),
        dump_ (path) {

}




////////////////////////////////////////////////////////////////////////////
// process()
//      Does actual processing a minidump file
StatusCode Triage::process() {


    //proc_ = (&symbolSupplier_, &resolver, true);
    ProcessResult   sc;

    if( !dump_.Read() ) {
        cerr << "Unable to read dumpfile." << endl;
        return StatusCode::ERROR;
    }

    sc = proc_.Process( &dump_, &state_);    
    
    if( PROCESS_OK!=sc ) {
        cerr << "Unable to process dumpfile." << endl;
        return StatusCode::ERROR;
    }

    // Calculate score from breakpad
    
    cout << "-----------------------------------------------" << endl;
    cout << path_ << endl;

    dirPath_ = fs::path(path_);
    dirPath_ = dirPath_.parent_path();

    fs::path jsonPath(dirPath_.string());
    jsonPath.append("crash.json");

    
    // There is a bug in Visual Studio that doesn't let you do this the sane way...
    vector< unique_ptr<Xploitability> > modules;
    modules.push_back( make_unique<XploitabilityBreakpad>( &dump_, &state_) );
    modules.push_back( make_unique<XploitabilityBangExploitable>( &dump_, &state_) );    

    for( const auto& mod : modules ) {
        const auto result   = mod->process();
        results_.push_back( result );
    }

    tracer_  = make_unique<XploitabilityTracer>( &dump_, &state_, jsonPath.string());
    const auto result   = tracer_->process();
    results_.push_back( result );

    fs::path outpath(dirPath_.string());
    outpath.append("triage.json");
    persist(outpath.string());
    
    return StatusCode::GOOD;
}

////////////////////////////////////////////////////////////////////////////
// normalize()
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
// triagePath()
const string Triage::triagePath() {
    fs::path  tPath;
    tPath.append( exploitability() );
    tPath.append( crashReason() );    
    return tPath.generic_string();
}

////////////////////////////////////////////////////////////////////////////
// crashReason()
const string Triage::crashReason()  const {
    string ret;
    regex regexFilter { "[^a-zA-Z0-9_]+" };

    if(  state_.crash_reason().size()>0 ) {
        ret = state_.crash_reason();
    } else {
        ret =  "Unknown";
    }

    ret = regex_replace( ret, regexFilter, "_" );
    return ret;
}

const uint64_t Triage::crashAddress() const { 
    return state_.crash_address();
}

////////////////////////////////////////////////////////////////////////////
// exploitability()
//      returns value from 0.0 to 1.0 for exploitabilty
XploitabilityRank Triage::exploitabilityRank() const {
    
    XploitabilityRank rank = XploitabilityRank::XPLOITABILITY_NONE;

    for( auto arank : ranks() ) {
        if( arank > rank ) {
            rank = arank;
        }
    }

    return rank;

}

const string Triage::exploitability() const {
    //return Xploitability::rankToString( exploitabilityRank() );
    XploitabilityRank rank = exploitabilityRank();
    
    return ~rank;
}


vector<XploitabilityRank>   Triage::ranks() const {
    vector<XploitabilityRank> ret;
    for( auto result : results_ ) {
        ret.push_back(result.rank);
    }
    return ret;
}

const string Triage::ranksString() const {
    ostringstream ss;
    for( auto& rank : ranks() ) {
        ss << rank << " ";
    }
    return ss.str();
}


const string Triage::path() const {
    return path_;
}



json Triage::toJson() const {
    return json{
        { "crashReason",        crashReason() },
        { "crashAddress",       crashAddress() },
        { "exploitability",     exploitability() },
        { "minidumpPath",       path() },
        { "ranks",              ranks() },
        { "rank",               exploitabilityRank() },
        { "instructionPointer", instructionPtr_, },
        { "stackPointer",       stackPtr_, },
        { "tracer",             tracer_->toJson() }
    };
}

void Triage::persist(const string path)  const {
    ofstream ofs(path);
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
    os << "Tag           : "        << self.triagePath()            << endl;
    return os;  
}  
  


} // namespace