#include "Xploitability.h"
#include <string>

using namespace std;

namespace sl2 {


string operator~( XploitabilityRank& self ) {
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


ostream& operator<<( ostream& os, XploitabilityRank& self ) {
    return os << ~self;
}

ostream& operator<<( ostream& os, XploitabilityResult& result ) {
    return os << result.rank;
}


Xploitability::~Xploitability( ) {
    if( disassembler_!=nullptr )
        delete disassembler_;
}

Xploitability::Xploitability( Minidump* dmp, ProcessState* state, string moduleName )
        : Exploitability(dmp, state), name_(moduleName) {


    MinidumpException* exception = dump_->GetException();
    if (!exception) {
        throw "No Exception record";
    }

    rawException_ = exception->exception();
    if  (!rawException_) {
        throw "Can't get raw exception";
    }

    context_ = exception->GetContext();
    if (!context_) {
        throw "Can't get context";
    }

    memoryList_ = dump_->GetMemoryList();
    
    if (!memoryList_) {        
        memoryAvailable_ = false;
    }

    exceptionCode_ = rawException_->exception_record.exception_code;

    if (!context_->GetInstructionPointer(&instructionPtr_)) {
        throw "can't get pc";
    }

    // Getting the stack pointer.
    if (!context_->GetStackPointer(&stackPtr_)) {
        throw "Can't get stack pointer.";
    }

    if(!memoryAvailable_)
        return;
        
    size_t bufsz = 15;
    MinidumpMemoryRegion* instrRegion =
        memoryList_->GetMemoryRegionForAddress(instructionPtr_);
    if(!instrRegion)
        return;
    const uint8_t *rawMem = instrRegion->GetMemory() + bufsz;
    if(!rawMem)
        return;
    disassembler_ = new DisassemblerX86(rawMem, bufsz,  instructionPtr_);
    
}


////////////////////////////////////////////////////////////////////////////
// CheckPlatformExploitability()
//      Killing the function from usage
ExploitabilityRating Xploitability::CheckPlatformExploitability() {
    throw "Do not use this stupid function";
    return ExploitabilityRating();
}



bool Xploitability::isExceptionAddressInUser() {
    // Assuming 64bit
    return process_state_->crash_address() <= 0x7fffffffffffffff;    
}


bool Xploitability::isExceptionAddressNearNull() {
    return process_state_->crash_address() <= 64*0x400;
}


} // namespace