// XXX_INCLUDE_TOB_COPYRIGHT_HERE

// Xploitability implementation for using sl2 tracer.cpp.  This scores based on taint information

#include "XploitabilityTracer.h"

#include <string>
#include <fstream>

using namespace std;

namespace sl2 {

/**
 * Default constructor. Uses tracer.cpp to calculate exploitability
 * @param dump minidump file spit out by tracer
 * @param process_state
 * @param crashJson JSON dump of tracer output
 */
XploitabilityTracer::XploitabilityTracer(
        Minidump *dump,
        ProcessState *process_state,
        const string crashJson )
    :   Xploitability(dump, process_state, "sl2"),
        crashJsonPath_(crashJson)  {
}

/**
 * Copies the tracer.cpp json into triage.json for extra information
 */
 json XploitabilityTracer::toJson() const {
    return json_;
 }

/**
 * Reads the crash.json file from tracer.cpp. There is potential to include information from the minidump processing here.
 */
XploitabilityResult XploitabilityTracer::process() {
    XploitabilityResult ret(name());


    // If we can't open the crash.json file, we return XPLOITABILITY_NONE
    uint32_t score  = 0;
    try {
        ifstream ifs (crashJsonPath_);
        json_ << ifs;
        score = json_["score"];
    } catch(...) {
    }

    // Convert the 0-100 ranking to our 0-4 . No information is lost
    // since tracer only has 5 possible values
    if(         score >= 100 ) {
        ret.rank = XploitabilityRank::XPLOITABILITY_HIGH;
    } else if(  score >= 75 ) {
        ret.rank = XploitabilityRank::XPLOITABILITY_MEDIUM;
    } else if(  score >= 50 ) {
        ret.rank = XploitabilityRank::XPLOITABILITY_LOW;
    } else if(  score >= 25 ) {
        ret.rank = XploitabilityRank::XPLOITABILITY_UNKNOWN;
    } else {
        ret.rank = XploitabilityRank::XPLOITABILITY_NONE;
    }
    return ret;
}


} // namespace
