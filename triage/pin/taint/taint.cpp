#include "pin.H"
#include <sys/syscall.h>
#include <signal.h>
#include <iostream>
#include <fstream>
#include <string>
#include <set>
#include <map>

#define DEBUG

UINT64 threadCount = 0; 

bool saveRetOpen = false;
bool saveRetRead = false;
bool debug = false;

string taintFile = "__STDIN";
string fname = "";
ADDRINT start;

std::map<UINT64, string> FDLookup;
std::set<ADDRINT> tainted_addrs;
std::set<LEVEL_BASE::REG> tainted_regs;

std::ostream *out = &cerr;

VOID Fini(INT32 code, VOID *v)
{
    *out <<  "===============================================" << endl;
    *out << tainted_addrs.size() << ", " << tainted_regs.size() << std::endl;
}

VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v) {
    threadCount++;
}

VOID propagate_taint(CONTEXT *ctx) {
    return;
}

bool reg_is_tainted(LEVEL_BASE::REG reg) {
    REG fullReg = REG_FullRegName(reg);
    bool tainted = tainted_regs.find(fullReg) != tainted_regs.end();
    
#ifdef DEBUG
    if(tainted) {
        *out << REG_StringShort(fullReg) << " is tainted" << std::endl;
    } else {
        *out << REG_StringShort(fullReg) << " is not tainted" << std::endl;
    }
#endif

    return tainted;
}

VOID reg_taint(LEVEL_BASE::REG reg) {
    REG fullReg = REG_FullRegName(reg);
#ifdef DEBUG
    *out << "TAINTING: " << REG_StringShort(fullReg) << std::endl;
#endif
    tainted_regs.insert(fullReg);
}

VOID reg_untaint(LEVEL_BASE::REG reg) {
    REG fullReg = REG_FullRegName(reg);
#ifdef DEBUG
    *out << "UNTAINTING: " << REG_StringShort(fullReg) << std::endl;
#endif
    std::set<LEVEL_BASE::REG>::iterator it = tainted_regs.find(fullReg);
    if(it != tainted_regs.end()) {
        tainted_regs.erase(it);
    }
}

bool mem_is_tainted(ADDRINT mem) {
    bool tainted = tainted_addrs.find(mem) != tainted_addrs.end();
    return tainted;
}

VOID mem_taint_reg(REG reg, ADDRINT mem,  UINT32 size) {
    bool tainted = false;
    for(UINT32 i=0; i<size; i++) {
        if(mem_is_tainted(mem+i)) {
            tainted = true;
            break;
        }
    }

    if(tainted) {
#ifdef DEBUG
        *out << std::hex << mem << " - " << mem+size << " is tainted" << std::endl;
#endif
        reg_taint(reg);
    } else {
#ifdef DEBUG
        *out << std::hex << mem << " - " << mem+size << " is not tainted" << std::endl;
#endif
        reg_untaint(reg);
    }
}

VOID mem_untaint(ADDRINT mem, UINT32 size) {
#ifdef DEBUG
    *out << "UNTAINTING: " << std::hex << mem << " - " << mem+size << std::endl;
#endif

    for(UINT32 i=0; i<size; i++) {
        std::set<ADDRINT>::iterator it = tainted_addrs.find(mem+i);   
        if(it != tainted_addrs.end()) {
            tainted_addrs.erase(it);
        }
    }
}

VOID mem_taint(ADDRINT mem, UINT32 size) {
#ifdef DEBUG
    *out << "TAINTING: " << std::hex << mem << " - " << mem+size << std::endl;
#endif

    for(UINT32 i=0; i<size; i++) {
        tainted_addrs.insert(mem+i);
    }
}

VOID Insn(INS ins, VOID *v) {
#ifdef DEBUG
    *out << std::endl;
    *out << INS_Disassemble(ins) << std::endl;        
#endif

    if(INS_OperandCount(ins) < 2) {
        return;
    }

    if(INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
#ifdef DEBUG
        *out << "MEM READ" << std::endl;
        *out << "**** **** W" << std::endl;
#endif
        for(uint32_t i=0; i<INS_MaxNumWRegs(ins); i++) {
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)mem_taint_reg,
                IARG_UINT32, INS_RegW(ins, i),
                IARG_MEMORYOP_EA, 0,
                IARG_UINT32, (UINT32)INS_MemoryReadSize(ins),
                IARG_END);
        }
    } else if(INS_MemoryOperandIsWritten(ins, 0)) {
#ifdef DEBUG
        *out << "MEM WRIT" << std::endl;
        *out << "**** **** R" << std::endl;
#endif
        bool tainted = false;
        for(uint32_t i=0; i<INS_MaxNumRRegs(ins); i++) {
            // *out << REG_StringShort(INS_RegR(ins, i)) << std::endl;
            tainted |= reg_is_tainted(INS_RegR(ins, i));
        }

        if(tainted) {
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)mem_taint,
                IARG_MEMORYOP_EA, 0,
                IARG_MEMORYWRITE_SIZE,
                IARG_END);
        } else {
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)mem_untaint,
                IARG_MEMORYOP_EA, 0,
                IARG_MEMORYWRITE_SIZE,
                IARG_END);
        }
    } else if(INS_OperandIsReg(ins, 0)) {
#ifdef DEBUG
        *out << "REG REG" << std::endl;
        *out << "**** **** R" << std::endl;
#endif
        bool tainted = false;
        for(uint32_t i=0; i<INS_MaxNumRRegs(ins); i++) {
            // *out << REG_StringShort(INS_RegR(ins, i)) << std::endl;
            tainted |= reg_is_tainted(INS_RegR(ins, i));
        }

#ifdef DEBUG
        *out << "**** **** W" << std::endl;
#endif
        for(uint32_t i=0; i<INS_MaxNumWRegs(ins); i++) {
            // *out << REG_StringShort(INS_RegW(ins, i)) << std::endl;
            if(tainted) {
                reg_taint(INS_RegW(ins, i));
            } else {
                reg_untaint(INS_RegW(ins, i));
            }
        }
    }
}

void handle_read(CONTEXT *ctx, SYSCALL_STANDARD std) {
    ADDRINT fd = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 0)));
    start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));

    if(FDLookup.find(fd) != FDLookup.end() && FDLookup[fd].find(taintFile) != string::npos) {
#ifdef DEBUG
        ADDRINT size  = PIN_GetSyscallArgument(ctx, std, 2);
        *out << "READ of " << FDLookup[fd] << " for size 0x" << std::hex << size << " to 0x" << start << std::endl;
#endif
        saveRetRead = true;
    }

}

void handle_open(CONTEXT *ctx, SYSCALL_STANDARD std) {
    fname = reinterpret_cast<char *>((PIN_GetSyscallArgument(ctx, std, 0)));
    saveRetOpen = true;
}

VOID SyscallEntry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
    switch(PIN_GetSyscallNumber(ctx, std)) {
        case __NR_read:
            handle_read(ctx, std);
            break;
        case __NR_open:
            handle_open(ctx, std);
            break;
    }
}

VOID SyscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
    if (saveRetOpen){
        unsigned long fd = PIN_GetSyscallReturn(ctx, std);
        FDLookup[fd] = fname;
        saveRetOpen = false;
    } else if (saveRetRead) {
        unsigned long byteCount = PIN_GetSyscallReturn(ctx, std);
        mem_taint(start, byteCount);

#ifdef DEBUG
        *out << "READCNT 0x" << std::hex << byteCount << std::endl;
#endif
        saveRetRead = false;
    }
}

BOOL HandleSignal(THREADID tid, INT32 sig, CONTEXT *ctx, BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v) {
    *out << "S E G F A U L T " << std::endl;
    std::set<LEVEL_BASE::REG>::iterator it;
    for(it = tainted_regs.begin(); it != tainted_regs.end(); it++) {
        *out << REG_StringShort(*it) << " has taint" << std::endl;
    }
    return true;
}

int main(int argc, char *argv[]) {
    PIN_Init(argc, argv);

    FDLookup[0] = "__STDIN";
    FDLookup[1] = "__STDOUT";
    FDLookup[2] = "__STDERR";

    string fileName = "out.txt";
    if (!fileName.empty()) { 
        out = new std::ofstream(fileName.c_str());
    }

    INS_AddInstrumentFunction(Insn, 0);
    PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    PIN_AddSyscallExitFunction(SyscallExit, 0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_InterceptSignal(SIGSEGV, HandleSignal, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
