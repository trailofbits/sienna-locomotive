#ifndef Xploitability_H
#define Xploitability_H


#include <string>
#include <sstream>

#include "google_breakpad/common/breakpad_types.h"
#include "google_breakpad/processor/exploitability.h"
#include "google_breakpad/processor/process_state.h"
#include "processor/disassembler_x86.h"


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

    friend ostream& operator<<( ostream& os, XploitabilityResult& result );
};


class Xploitability : public Exploitability {

public:

    Xploitability( Minidump* dmp, ProcessState* state, string name );
    ~Xploitability( );
    
    virtual XploitabilityResult             process() = 0;

    bool isExceptionAddressInUser();
    bool isExceptionAddressNearNull();

    string name() { return name_; }


protected:
    

    virtual ExploitabilityRating            CheckPlatformExploitability() final;
    XploitabilityRank               rank_;
    const MDRawExceptionStream*     rawException_;
    const MinidumpContext*          context_;
    uint64_t                        stackPtr_           = 0;
    uint64_t                        instructionPtr_     = 0;
    uint32_t                        exceptionCode_      = 0;
    bool                            memoryAvailable_    = true;
    MinidumpMemoryList*             memoryList_;
    string                          name_;
    DisassemblerX86*                disassembler_       = nullptr;

};


} // namespace

#endif