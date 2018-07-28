// XXX_INCLUDE_TOB_COPYRIGHT_HERE
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
ostream& operator<<( ostream& os, const XploitabilityRank& self );
const string operator~( const XploitabilityRank& self );





////////////////////////////////////////////////////////////////////////////
// XploitabilityResult
////////////////////////////////////////////////////////////////////////////
class XploitabilityResult {
public:
    XploitabilityRank       rank;
    const string            moduleName;
    

    XploitabilityResult( const string modName ):
        moduleName(modName) {
        rank = XploitabilityRank::XPLOITABILITY_NONE;
    };

    friend ostream& operator<<( ostream& os, const XploitabilityResult& result );
};


class Xploitability : public Exploitability {

public:

    Xploitability( Minidump* dmp, ProcessState* state, const string name );
    ~Xploitability(  ){};
    
    virtual XploitabilityResult             process() = 0;

    bool            isExceptionAddressInUser() const;
    bool            isExceptionAddressNearNull() const;

    const string    name() const                { return name_; };
    const uint64_t  instructionPointer() const  { return instructionPtr_; };
    const uint64_t  stackPointer() const        { return stackPtr_; };


protected:

    virtual ExploitabilityRating    CheckPlatformExploitability() final;

    MinidumpMemoryList*             memoryList_;
    XploitabilityRank               rank_;
    bool                            memoryAvailable_    = true;
    const MDRawExceptionStream*     rawException_;
    const MinidumpContext*          context_;
    const string                    name_;
    uint32_t                        exceptionCode_      = 0;
    uint64_t                        instructionPtr_     = 0;
    uint64_t                        stackPtr_           = 0;
    unique_ptr<DisassemblerX86>     disassembler_       = nullptr;

};


} // namespace

#endif