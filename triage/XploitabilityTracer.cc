#include "XploitabilityTracer.h"

#include <string>
#include <fstream>



using namespace std;

namespace sl2 {

XploitabilityTracer::XploitabilityTracer(  
        Minidump *dump,
        ProcessState *process_state,
        const string crashJson )
    :   Xploitability(dump, process_state, "sl2"),
        crashJsonPath_(crashJson)  {


}


 json XploitabilityTracer::toJson() const { 
     return json_;
 }


XploitabilityResult XploitabilityTracer::process() { 
    XploitabilityResult ret(name());

    // If we can't open the crash.json file, we return XPLOITABILITY_NONE
    uint32_t score  = 0;
    try {
        ifstream ifs (crashJsonPath_);
        json_ << ifs;
        score = json_["score"];
    } catch(...) {
        return ret;
    }

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
