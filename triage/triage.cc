////////////////////////////////////////////////////////////////////////////
// Trail of Bits
// July 2018
////////////////////////////////////////////////////////////////////////////

#include "triage.h"


#include <iostream>
#include "google_breakpad/processor/minidump.h"
#include "google_breakpad/processor/minidump_processor.h"
#include "google_breakpad/processor/process_state.h"

#include "Xploitability.h"
#include "XploitabilityBreakpad.h"
#include "XploitabilityBangExploitable.h"
#include "XploitabilityTracer.h"

#include <algorithm>
#include <numeric>
#include <filesystem>
#include <regex>
#include <string>
#include <iterator>


// #include "cfi_frame_info.h"

using namespace std;
using namespace google_breakpad;
namespace fs = std::experimental::filesystem;

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

    fs::path mdumpPath;
    mdumpPath.append(path_);
    mdumpPath = mdumpPath.parent_path();
    mdumpPath.append("crash.jon");

    string jsonPath(mdumpPath.string());
    cout << "json file" << jsonPath << endl;
    
    Xploitability* x =nullptr;

    vector<Xploitability*> modules = { 
        new XploitabilityBreakpad( &dump_, &state_),
        new XploitabilityBangExploitable( &dump_, &state_),
        new XploitabilityTracer( &dump_, &state_, jsonPath )

    };


    for( auto& mod : modules ) {
        auto result = mod->process();
        ranks_.push_back( result.rank );
        delete mod;
    }
    
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
const string Triage::crashReason() {
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

////////////////////////////////////////////////////////////////////////////
// exploitability()
//      returns value from 0.0 to 1.0 for exploitabilty
XploitabilityRank Triage::exploitabilityRank() {
    
    XploitabilityRank rank = XploitabilityRank::XPLOITABILITY_NONE;

    for( auto arank : ranks_ ) {
        if( arank > rank ) {
            rank = arank;
        }
    }

    return rank;

}

const string Triage::exploitability() {
    //return Xploitability::rankToString( exploitabilityRank() );
    const XploitabilityRank rank = exploitabilityRank();
    
    return ~rank;
}


vector<XploitabilityRank>   Triage::ranks() {
    return ranks_;
}

const string Triage::ranksString() const {
    ostringstream ss;
    for( auto& rank : ranks_ ) {
        ss << rank << " ";
    }
    return ss.str();
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