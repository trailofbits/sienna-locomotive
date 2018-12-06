// XXX_INCLUDE_TOB_COPYRIGHT_HERE


#include "Xploitability.h"

#include <string>

using namespace std;

namespace sl2 {


/*!  Just converts to a string */
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

/*! strings for streams */
ostream& operator<<( ostream& os, const XploitabilityRank& self ) {
    return os << ~self;
}

/*! strings for streams */
ostream& operator<<( ostream& os, const XploitabilityResult& result ) {
    return os << result.rank;
}


string Xploitability::str() const {
    ostringstream oss;
    oss << this;
    return oss.str();
}


static string polybase( uint64_t addr ) {
    ostringstream oss;
    oss << "0x" << hex << addr;
    oss << " (" << dec << ")" << addr;
    return oss.str();
}


const MDRawContextAMD64* Xploitability::getContext() const {
    return context_->GetContextAMD64();
}

ostream& operator<<( ostream& os, Xploitability& self ) {
    const MDRawContextAMD64* ctx = self.context_->GetContextAMD64();
    os << "ip           : " <<polybase( self.instructionPointer() ) << endl;
    os << "stackPtr     : " <<polybase( self.stackPointer() ) << endl;
    os << "rip          : " <<polybase( ctx->rip ) << endl;
    os << "rsp          : " <<polybase( ctx->rsp ) << endl;
    os << "crash_address: " <<polybase( self.process_state_->crash_address() ) << endl;
    return os;
}

/**
 * Calculates exploitability given a minidump
 * @param dmp
 * @param state
 * @param moduleName
 */
Xploitability::Xploitability( Minidump* dmp, ProcessState* state, const string moduleName )
        : Exploitability(dmp, state), name_(moduleName) {


    MinidumpException* exception = dump_->GetException();
    if (!exception) {
        cout << " no exc rec" << endl;
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
    disassembler_ = make_unique<DisassemblerX86>(rawMem, bufsz,  instructionPtr_);

}

/** Unused - kills execution
 */
ExploitabilityRating Xploitability::CheckPlatformExploitability() {
    throw "Do not use this function"; // @WH what is this for? -- EH
    return ExploitabilityRating();
}


/**
 * @return whether the address of the exception was in user space
 */
bool Xploitability::isExceptionAddressInUser() const {
    // Assuming 64bit
    return process_state_->crash_address() <= 0x7fffffffffffffff;
}

/**
 * @return whether the address of the exception was suspiciously small
 */
bool Xploitability::isExceptionAddressNearNull() const {
    return process_state_->crash_address() <= 64*0x400;
}


} // namespace