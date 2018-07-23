#ifndef Xploitability_H
#define Xploitability_H

#include "google_breakpad/common/breakpad_types.h"
#include "google_breakpad/processor/exploitability.h"
#include "google_breakpad/processor/process_state.h"

using namespace google_breakpad;


namespace sl2 {

enum XploitabilityRank {
    XPLOITABILITY_HIGH      = 4,
    XPLOITABILITY_MEDIUM    = 3,
    XPLOITABILITY_LOW       = 2,
    XPLOITABILITY_UNKNOWN   = 1,
    XPLOITABILITY_NONE      = 0
};

class XploitabilityResult {
public:

    XploitabilityResult() :
        isFinal(false) {        
    }

    bool                    isFinal;
    XploitabilityRank       rank;
};


class Xploitability : public Exploitability {

public:
    
    Xploitability( Minidump* dmp, ProcessState* state ): Exploitability(dmp, state){  }
    //virtual double                  exploitabilityScore() = 0;
    virtual XploitabilityRank               rank() = 0;

    static string rankToString(XploitabilityRank r) {
        switch(r) {
            case XPLOITABILITY_HIGH:
                return "High";
            case XPLOITABILITY_MEDIUM:
                return "Medium";
            case XPLOITABILITY_LOW:
                return "Low";
            case XPLOITABILITY_UNKNOWN:
                return "Unknown";
            case XPLOITABILITY_NONE:
                return "None";
            default:
                return "None";
        }
    }

protected:
    virtual ExploitabilityRating    CheckPlatformExploitability() = 0;

    XploitabilityRank  rank_;

};


} // namespace

#endif