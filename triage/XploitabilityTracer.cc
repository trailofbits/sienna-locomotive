#include "XploitabilityTracer.h"

#include <string>
#include <fstream>



using namespace std;

namespace sl2 {

XploitabilityTracer::XploitabilityTracer(  
        Minidump *dump,
        ProcessState *process_state,
        const string crashJson )
    :   Xploitability(dump, process_state, "sl2")  {

    cout << "opening " << crashJson << endl;
    ifstream ifs (crashJson);
    json_ << ifs;
}


XploitabilityResult XploitabilityTracer::process() { 
    

    XploitabilityResult ret;
    cout << "XXX: " << json_ << endl;
    
    uint32_t score = json_["score"];    

    if(         100     >= score ) {
        ret.rank = XploitabilityRank::XPLOITABILITY_HIGH;
    } else if(  75      >= score ) {
        ret.rank = XploitabilityRank::XPLOITABILITY_MEDIUM;
    } else if(  50      >= score ) {
        ret.rank = XploitabilityRank::XPLOITABILITY_LOW;
    } else if(  25      >= score ) { 
        ret.rank = XploitabilityRank::XPLOITABILITY_UNKNOWN;
    } else {
        ret.rank = XploitabilityRank::XPLOITABILITY_NONE;
    }
    return ret;
}



} // namespace
