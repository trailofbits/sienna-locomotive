#ifndef Xploitability_H
#define Xploitability_H


#include <string>
#include <sstream>

#include "google_breakpad/common/breakpad_types.h"
#include "google_breakpad/processor/exploitability.h"
#include "google_breakpad/processor/process_state.h"


using namespace google_breakpad;
using namespace std;

namespace sl2 {

enum class XploitabilityRank {
    XPLOITABILITY_HIGH      = 4,
    XPLOITABILITY_MEDIUM    = 3,
    XPLOITABILITY_LOW       = 2,
    XPLOITABILITY_UNKNOWN   = 1,    
    XPLOITABILITY_NONE      = 0

};




////////////////////////////////////////////////////////////////////////////
// XploitabilityResult
////////////////////////////////////////////////////////////////////////////
class XploitabilityResult {
public:
    XploitabilityRank       rank;
};


class Xploitability : public Exploitability {

public:

    Xploitability( Minidump* dmp, ProcessState* state );
    
    //virtual double                  exploitabilityScore() = 0;
    virtual XploitabilityRank               rank() = 0;

    bool isExceptionAddressInUser();
    bool isExceptionAddressNearNull();



protected:
    virtual ExploitabilityRating    CheckPlatformExploitability() = 0;

    XploitabilityRank               rank_;
    const MDRawExceptionStream*     rawException_;
    const MinidumpContext*          context_;
    uint64_t                        stackPtr_           = 0;
    uint64_t                        instructionPtr_     = 0;
    uint32_t                        exceptionCode_      = 0;
    bool                            memoryAvailable_    = true;
    MinidumpMemoryList*             memoryList_;
};


} // namespace

#endif