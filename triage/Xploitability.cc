#include "Xploitability.h"
#include <string>

using namespace std;

namespace sl2 {


const string operator~( const XploitabilityRank& self ) {
    switch(self) {
        case XploitabilityRank::XPLOITABILITY_HIGH:
            return "High";
        case XploitabilityRank::XPLOITABILITY_MEDIUM:
            return "Medium";
        case XploitabilityRank::XPLOITABILITY_LOW:
            return "Low";
        case XploitabilityRank::XPLOITABILITY_UNKNOWN:
            return "Unknown";
        case XploitabilityRank::XPLOITABILITY_NONE:
            return "None";
        default:
            return "None";
    }
}


ostream& operator<<( ostream& os, const XploitabilityRank& self ) {
    return os << ~self;
}

ostream& operator<<( ostream& os, const XploitabilityResult& result ) {
    return os << result.rank;
}


Xploitability::Xploitability( Minidump* dmp, ProcessState* state, const string moduleName )
        : Exploitability(dmp, state), name_(moduleName) {

    cout << "MinidumpException" << endl;
    MinidumpException* exception = dump_->GetException();
    if (!exception) {
        cout << " no exc rec" << endl;
        throw "No Exception record";
    }

    cout << "rawException_" << endl;
    rawException_ = exception->exception();
    if  (!rawException_) {
        throw "Can't get raw exception";
    }
    cout << "GetContext" << endl;

    context_ = exception->GetContext();
    if (!context_) {
        throw "Can't get context";
    }
    cout << "GetMemoryList" << endl;
    memoryList_ = dump_->GetMemoryList();    
    if (!memoryList_) {        
        memoryAvailable_ = false;
    }

    exceptionCode_ = rawException_->exception_record.exception_code;

    cout << "GetInstructionPointer" << endl;

    if (!context_->GetInstructionPointer(&instructionPtr_)) {
        throw "can't get pc";
    }
    cout << "GetStackPointer" << endl;

    // Getting the stack pointer.
    if (!context_->GetStackPointer(&stackPtr_)) {
        throw "Can't get stack pointer.";
    }
    cout << "memoryAvailable_" << endl;

    if(!memoryAvailable_)
        return;

    cout << "GetMemoryRegionForAddress" << endl;

    size_t bufsz = 15;
    MinidumpMemoryRegion* instrRegion =
        memoryList_->GetMemoryRegionForAddress(instructionPtr_);
    if(!instrRegion)
        return;
    cout << "GetMemory" << endl;

    const uint8_t *rawMem = instrRegion->GetMemory() + bufsz;
    if(!rawMem)
        return;
    disassembler_ = make_unique<DisassemblerX86>(rawMem, bufsz,  instructionPtr_);


    
}


////////////////////////////////////////////////////////////////////////////
// CheckPlatformExploitability()
//      Killing the function from usage
ExploitabilityRating Xploitability::CheckPlatformExploitability() {
    throw "Do not use this stupid function";
    return ExploitabilityRating();
}



bool Xploitability::isExceptionAddressInUser() const {
    // Assuming 64bit
    return process_state_->crash_address() <= 0x7fffffffffffffff;    
}


bool Xploitability::isExceptionAddressNearNull() const {
    return process_state_->crash_address() <= 64*0x400;
}


} // namespace