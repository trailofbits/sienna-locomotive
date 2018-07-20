////////////////////////////////////////////////////////////////////////////
// Trail of Bits
// July 2018
////////////////////////////////////////////////////////////////////////////
#include <string>
#include "triage.h"


#include <iostream>
#include "google_breakpad/processor/minidump.h"
#include "google_breakpad/processor/minidump_processor.h"
#include "google_breakpad/processor/process_state.h"
#include "exploitability_sl2.h"
#include <algorithm>
#include <numeric>
#include <filesystem>
#include <regex>


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

Triage::~Triage( )  {
    delete xploitabilityBreakpad_;
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
    xploitabilityBreakpad_ = new ExploitabilitySL2( &dump_, &state_);
    xploitabilityBreakpad_->CheckPlatformExploitability();
    scores_.push_back( xploitabilityBreakpad_->exploitabilityScore()  );

    
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
double Triage::exploitabilityScore() {
    double ret = 0.0;

    if( scores_.size()==0 ) {
        return 0.0;
    }
    
    for( auto score : scores_  ) {
        score  = Triage::normalize(score);
        ret += score;
    }

    return ret / scores_.size();


}

const string Triage::exploitability() {

    double score = exploitabilityScore();
    if(         kHighCutoff   <= score ) {
        return "High";
    } else if(  kMediumCutoff <= score ) {
        return "Medium";
    } else if(  kLowCutoff    <= score ) {
        return "Low";
    } else if(  kInterestingCutoff <= score ) {
        return "Interesting";
    } else  {
        return "None";
    }
}

////////////////////////////////////////////////////////////////////////////
// <<()
ostream& operator<<(ostream& os, Triage& self) {

    os << "Exploitability Score: "  << self.exploitabilityScore()   << endl;
    os << "Exploitability Rating: " << self.exploitability()        << endl;
    os << "Crash Reason: "          << self.crashReason()           << endl;
    os << "Tag: "                   << self.triagePath()           << endl;
    return os;  
}  
  


} // namespace