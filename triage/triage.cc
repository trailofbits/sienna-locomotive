// XXX_INCLUDE_TOB_COPYRIGHT_HERE

// This is the main triage class that works on a single minidump file (versus triager.cc which handles command line, multiple files, etc.
// It runs the 3 processors (!exploitable, breakpad, and tracer) on the minidump.  The tracer processor is a little special since it can
// have our taint information.  From the processors the highest score is used for the exploitability.  The exploitability and important
// details from the crash and minidump analysis are put in a triage.json file.

#include "triage.h"

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
#include "google_breakpad/processor/minidump.h"
#include "google_breakpad/processor/minidump_processor.h"
#include "google_breakpad/processor/process_state.h"
#include "google_breakpad/processor/call_stack.h"
#include "google_breakpad/processor/stack_frame.h"
#include "stackwalk_common.h"




using namespace std;
using namespace google_breakpad;

using google_breakpad::MinidumpProcessor;
using google_breakpad::ProcessState;
using google_breakpad::SimpleSymbolSupplier;

namespace sl2 {



/**
 * Constructor for Triage class which loads a minidump file
 * @param minidumpPath path to the minidump to load
 */
Triage::Triage( const string& minidumpPath )
    :   minidumpPath_(minidumpPath),
        symbolSupplier_(minidumpPath),
        proc_(&symbolSupplier_, &resolver_, true),
        dump_ (minidumpPath) {

}

/**
 * Reads in the minidump and calls breakpad
 * @return success code
 */
StatusCode Triage::preProcess() {
    ProcessResult   sc;

    // Read in minidump
    if( !dump_.Read() ) {
        return StatusCode::ERROR;
    }


    // Do some breakpad processing
    sc = proc_.Process( &dump_, &state_);
    if( PROCESS_OK!=sc ) {
        return StatusCode::ERROR;
    }

    return StatusCode::GOOD;
}


/**
 * Does actual processing a minidump file
 * @return Status code
 */
StatusCode Triage::process() {


    StatusCode   sc;

    sc = preProcess();
    if( StatusCode::GOOD!=sc ) {
        cerr << "Unable to process dumpfile." << endl;
        return StatusCode::ERROR;
    }


    cout << "-----------------------------------------------" << endl;
    cout << minidumpPath_ << endl;
    cout << "Crashash: " << crashash() << endl;




    // There is a bug in Visual Studio that doesn't let you do this the sane way...
    vector< unique_ptr<Xploitability> > engine;
    engine.push_back( make_unique<XploitabilityBreakpad>( &dump_, &state_) );
    engine.push_back( make_unique<XploitabilityBangExploitable>( &dump_, &state_) );

    for( const unique_ptr<Xploitability>& mod : engine ) {
        processEngine(*mod);
        xploitabilityEngine_ = mod.get();
    }

    // Write the final triage information to the triage.json file
    // fs::path outminidumpPath(dirPath_.string());
    // outminidumpPath.append("triage.json");
    // persist(outminidumpPath.string());


    PrintProcessState( state_, true, &resolver_);


    const ProcessState& process_state = state_;
    PrintProcessStateMachineReadable(process_state);
    cout << toJson() << endl;

    // It's all good.
    return StatusCode::GOOD;
}



/**
 * process a single exploitability engine
 * @param x Which exploitability engine (!exploitable, tracer, breakpad) to use
 */
void Triage::processEngine(Xploitability& x) {
    try {
        cout << "Processing engine: " << x.name() << endl;
        const auto result   = x.process();
        results_.push_back( result );
        cout << result << endl;
    } catch( string& x1 ) {
        cerr << x1 << endl;
    } catch( exception& x2 ) {
        cerr << x2.what() << endl;
    } catch(...) {
        cerr << "processEngine() error" << endl;
    }
}


/**
 * Normalizes scores between 0 and 1
 */
double Triage::normalize(double x) {
    x = std::max(0.0,   x);
    x = std::min(1.0,   x);
    return x;
}

int Triage::signalType() {
    return 0;
}


/**
 * Retrieves the call stack from the minidump
 * @return Vector of stack frames
 */
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


/**
 * Returns the hash of the callstack.  This should uniquely identifiy
 * a crash (even with ASLR) by using the last 3 nibbles of the offset for each call in the callstack.
 * The format is a 6 nibble hex value.  The top 12 bits are the major hash, the bottom 12 bits are the minor hash.
 * The major hash relates to where it crashes, and the minor is of the callstack
 * @return crash hash
 */
const string Triage::crashash() const {
    uint64_t    stackhash = 0;
    auto calls = callStack();
    sort( calls.begin(), calls.end() );
    auto last  = unique(calls.begin(), calls.end());
    calls.erase(last, calls.end());

    for( uint64_t addr : calls ) {
        // We only want the 12 bits of the offset to ignore aslr
        addr &= 0xFFF;
        if( stackhash==0 )
            stackhash = addr<<12;
        stackhash ^= addr;
    }

    ostringstream oss;
    oss << setfill('0') << setw(6) << hex << stackhash;
    return oss.str();
}

/**
 * A tag is basically a string that uniquely identifies the crash.
 * It includes exploitability, crash reason, and eventually a unique address
 * @return tag
 */
const string Triage::triageTag() const {
    fs::path  tPath;
    tPath.append( exploitability() );
    tPath.append( crashReason() );
    tPath.append(crashash());
    string ret =  tPath.generic_string();
    return ret;
}

/**
 * The reason for the crash as far as the exception that caused it.
 * @return Stringified reason
 */
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

/**
 * @return Memory address where the crash occurred
 */
const uint64_t Triage::crashAddress() const {
    return state_.crash_address();
}

/**
 * @return the stack pointer when the crash occurred
 */
const uint64_t Triage::stackPointer() const {
    return xploitabilityEngine_->stackPointer();
}

/**
 * @return instruction pointer when the crash occurred
 */
const uint64_t Triage::instructionPointer() const {
    return xploitabilityEngine_->instructionPointer();
}


/**
 * @return  value from 0 to 4 for exploitability.  0 being None, 4 being High
 */
XploitabilityRank Triage::exploitabilityRank() const {
    XploitabilityRank rank = XploitabilityRank::XPLOITABILITY_NONE;
    for( auto arank : ranks() ) {
        if( arank > rank ) {
            rank = arank;
        }
    }
    return rank;
}


/*! @return Stringified exploitability rank */
const string Triage::exploitability() const {
    //return Xploitability::rankToString( exploitabilityRank() );
    XploitabilityRank rank = exploitabilityRank();
    return ~rank;
}


/**
 * @return a vector of the ranks from the 3 engines
 */
vector<XploitabilityRank>   Triage::ranks() const {
    vector<XploitabilityRank> ret;
    for( auto result : results_ ) {
        ret.push_back(result.rank);
    }
    return ret;
}


/**
 * @return Stringified version of all three ranks
 */
const string Triage::ranksString() const {
    ostringstream ss;
    for( auto& rank : ranks() ) {
        ss << rank << " ";
    }
    return ss.str();
}

/**
 * @return Path to the minidump file which was analyzed
 */
const string Triage::minidumpPath() const {
    return minidumpPath_;
}


/**
 * Converts a Triage object into a json object for persistence
 * @return the json object
 */
json Triage::toJson() const {
    auto ctx = xploitabilityEngine_->getContext();
    return json{
        { "crashReason",        crashReason() },
        { "crashAddress",       crashAddress() },
        { "exploitability",     exploitability() },
        { "tag",                triageTag() },
        { "callStack",          callStack() },
        { "crashash",           crashash() },
        { "minidumpPath",       minidumpPath() },
        { "ranks",              ranks() },
        { "rank",               exploitabilityRank() },
        { "instructionPointer", instructionPointer() },
        { "stackPointer",       stackPointer() },
        { "triage",             xploitabilityEngine_->str() },
        { "context_flags",      ctx->context_flags },
        { "cs",                 ctx->cs },
        { "dr0",                ctx->dr0 },
        { "dr1",                ctx->dr1 },
        { "dr2",                ctx->dr2 },
        { "dr3",                ctx->dr3 },
        { "dr6",                ctx->dr6 },
        { "dr7",                ctx->dr7 },
        { "ds",                 ctx->ds },
        { "eflags",             ctx->eflags },
        { "es",                 ctx->es },
        { "fs",                 ctx->fs },
        { "gs",                 ctx->gs },
        { "mx_csr",             ctx->mx_csr },
        { "r10",                ctx->r10 },
        { "r11",                ctx->r11 },
        { "r12",                ctx->r12 },
        { "r13",                ctx->r13 },
        { "r14",                ctx->r14 },
        { "r15",                ctx->r15 },
        { "r8",                 ctx->r8 },
        { "r9",                 ctx->r9 },
        { "rax",                ctx->rax },
        { "rbp",                ctx->rbp },
        { "rbx",                ctx->rbx },
        { "rcx",                ctx->rcx },
        { "rdi",                ctx->rdi },
        { "rdx",                ctx->rdx },
        { "rip",                ctx->rip },
        { "rsi",                ctx->rsi },
        { "rsp",                ctx->rsp },
        { "ss",                 ctx->ss }
    };
}


/*! Writes a triage object to triage.json */
void Triage::persist(const string minidumpPath)  const {
    ofstream ofs(minidumpPath);
    json j = toJson();
    ofs << j << endl;
    ofs.close();
}


/*! Print operator */
ostream& operator<<(ostream& os, Triage& self) {
    os << "Exploitability: "        << self.exploitability()        << endl;
    os << "Ranks         : "        << self.ranksString()           << endl;
    os << "Crash Reason  : "        << self.crashReason()           << endl;
    os << "Tag           : "        << self.triageTag()             << endl;
    return os;
}



} // namespace
