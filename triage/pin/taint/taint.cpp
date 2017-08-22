#include "pin.H"
#include "crash_data.h"

#include <sys/syscall.h>
#include <signal.h>
#include <iostream>
#include <fstream>
#include <string>
#include <list>
#include <set>
#include <map>

CrashData crash_data;
string fname = "";

// syscall control
bool saveRetOpen = false;
bool saveRetRead = false;
bool saveRetMmap = false;
bool debug = false;

// mmap
ADDRINT size;
std::map<ADDRINT, ADDRINT> execd;

// files
ADDRINT start;
string taintFile = "__STDIN";
std::map<UINT64, string> FDLookup;

// malloc
std::map<VOID *, SIZE> allocd;
std::map<VOID *, SIZE> freed;
std::set<VOID *> alloc_set;
std::set<VOID *> free_set;

std::ostream *out = &cout;

/*** TAINT ***/

VOID mem_taint_reg(ADDRINT ip, std::string *ptr_disas, 
        std::list<LEVEL_BASE::REG> *ptr_regs_r, std::list<LEVEL_BASE::REG> *ptr_regs_w, 
        ADDRINT mem,  UINT32 size) {
    crash_data.mem_to_reg(ip, ptr_disas, ptr_regs_r, ptr_regs_w, mem, size);
}

VOID regs_taint_mem(ADDRINT ip, std::string *ptr_disas, std::list<LEVEL_BASE::REG> *ptr_regs, ADDRINT mem, UINT32 size) {
    crash_data.regs_to_mem(ip, ptr_disas, ptr_regs, mem, size);
}

VOID regs_taint_regs(ADDRINT ip, std::string *ptr_disas, 
        std::list<LEVEL_BASE::REG> *ptr_regs_r, std::list<LEVEL_BASE::REG> *ptr_regs_w) {
    crash_data.regs_to_regs(ip, ptr_disas, ptr_regs_r, ptr_regs_w);
}

VOID handle_indirect(ADDRINT ip, std::string *ptr_disas, LEVEL_BASE::REG reg, ADDRINT regval, BOOL isRet) {
    crash_data.taint_indirect(ip, ptr_disas, reg, regval, execd, isRet);
}

VOID wrap_reg_untaint(ADDRINT ip, std::string *ptr_disas, LEVEL_BASE::REG reg) {
    std::list<TaintData*>::iterator taint_it;
    for(taint_it = crash_data.taint_data_list.begin(); taint_it != crash_data.taint_data_list.end(); taint_it++) {
        TaintData *ptr_taint_data = *taint_it;
        ptr_taint_data->reg_untaint(ip, ptr_disas, reg);
    }
}

/*** INSTRUCTION ***/

VOID record(ADDRINT addr) {
    crash_data.last_addrs.push_back(addr);
    while(crash_data.last_addrs.size() > RECORD_COUNT) {
        ADDRINT addr = crash_data.last_addrs.front();
        crash_data.last_addrs.pop_front();

        std::list<ADDRINT> last_addrs = crash_data.last_addrs;
        bool contains = (std::find(last_addrs.begin(), last_addrs.end(), addr) != last_addrs.end());
        if(!contains) {
            crash_data.insns.erase(addr);
        }
    }
}

VOID record_call(ADDRINT target, ADDRINT loc) {
    crash_data.last_calls.push_back(target);
    while(crash_data.last_calls.size() > RECORD_COUNT) {
        crash_data.last_calls.pop_front();
    }
}

BOOL handle_specific(INS ins) {
    OPCODE opcode = INS_Opcode(ins);

    // NOP
    if(opcode == 0x1c7) {
        // skip
        return true;
    }

    // indirect jump, indirect call
    if(INS_IsIndirectBranchOrCall(ins)) {
        if(debug) {
            *out << "INDIRECT: " << REG_StringShort(INS_RegR(ins, 0)) << std::endl;
        }

        INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)handle_indirect,
                IARG_INST_PTR,
                IARG_PTR, new std::string(INS_Disassemble(ins)),
                IARG_UINT32, INS_RegR(ins, 0),
                IARG_REG_VALUE, INS_RegR(ins, 0),
                IARG_BOOL, INS_IsRet(ins),
                IARG_END);
        return true;
    }

    // POP
    if(opcode == 0x249) {
        std::list<LEVEL_BASE::REG> *ptr_regs_r = new std::list<LEVEL_BASE::REG>();
        std::list<LEVEL_BASE::REG> *ptr_regs_w = new std::list<LEVEL_BASE::REG>();

        for(uint32_t i=0; i<INS_MaxNumRRegs(ins); i++) {
            ptr_regs_r->push_back(INS_RegR(ins, i));
        }

        for(uint32_t i=0; i<INS_MaxNumWRegs(ins); i++) {
            if(INS_RegW(ins, i) == REG_STACK_PTR)
                continue; 

            ptr_regs_w->push_back(INS_RegW(ins, i));
        }

        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)mem_taint_reg,
            IARG_INST_PTR,
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_PTR, ptr_regs_r,
            IARG_PTR, ptr_regs_w,
            IARG_MEMORYOP_EA, 0,
            IARG_UINT32, (UINT32)INS_MemoryReadSize(ins),
            IARG_END);

        return true;
    }

    // XOR
    if(opcode == 0x5e4) { 
        // handle xor a, a
        if(INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1) && INS_RegR(ins, 0) == INS_RegR(ins, 1)) {
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)wrap_reg_untaint,
                IARG_INST_PTR,
                IARG_PTR, new std::string(INS_Disassemble(ins)),
                IARG_UINT32, INS_RegR(ins, 0),
                IARG_END);
            return true;
        } 

        return false; 
    }

    if(INS_IsCall(ins) && INS_IsDirectBranchOrCall(ins)) {
        INS_InsertCall(ins, 
            IPOINT_BEFORE, 
            (AFUNPTR)record_call, 
            IARG_ADDRINT, INS_DirectBranchOrCallTargetAddress(ins),
            IARG_ADDRINT, INS_Address(ins),
            IARG_END);
        return false;
    } 

    return false;
}

VOID Insn(INS ins, VOID *v) {
    // pass address, disassembled insn to all insert calls
    string disas = INS_Disassemble(ins);
    
    ADDRINT ip = INS_Address(ins);
    
    if(!crash_data.insns.count(ip)) {
        Instruction insn(ip, disas);
        crash_data.insns[ip] = insn;
    } 

    /*
        Special cases
            xor reg, reg -> clear taint
            indirect branches and calls
    */
    
    INS_InsertCall(ins, 
        IPOINT_BEFORE, (AFUNPTR)record,
        IARG_ADDRINT, INS_Address(ins),
        IARG_END);
    
    if(handle_specific(ins)) {
        return;
    }

    if(INS_OperandCount(ins) < 2) {
        // mostly nops and nots
        if(debug) {
            *out << "5: " << disas << std::endl;
        }
        return;
    }

    if(INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
        std::list<LEVEL_BASE::REG> *ptr_regs_r = new std::list<LEVEL_BASE::REG>();
        std::list<LEVEL_BASE::REG> *ptr_regs_w = new std::list<LEVEL_BASE::REG>();

        for(uint32_t i=0; i<INS_MaxNumRRegs(ins); i++) {
            ptr_regs_r->push_back(INS_RegR(ins, i));
        }

        for(uint32_t i=0; i<INS_MaxNumWRegs(ins); i++) {
            ptr_regs_w->push_back(INS_RegW(ins, i));
        }

        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)mem_taint_reg,
            IARG_INST_PTR,
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_PTR, ptr_regs_r,
            IARG_PTR, ptr_regs_w,
            IARG_MEMORYOP_EA, 0,
            IARG_UINT32, (UINT32)INS_MemoryReadSize(ins),
            IARG_END);
        

    } else if(INS_MemoryOperandIsWritten(ins, 0)) {
        std::list<LEVEL_BASE::REG> *ptr_regs = new std::list<LEVEL_BASE::REG>();

        for(uint32_t i=0; i<INS_MaxNumRRegs(ins); i++) {
            ptr_regs->push_back(INS_RegR(ins, i));
        }

        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)regs_taint_mem,
            IARG_INST_PTR,
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_PTR, ptr_regs,
            IARG_MEMORYOP_EA, 0,
            IARG_MEMORYWRITE_SIZE,
            IARG_END);

    } else if(INS_OperandIsReg(ins, 0)) {
        std::list<LEVEL_BASE::REG> *ptr_regs_r = new std::list<LEVEL_BASE::REG>();
        std::list<LEVEL_BASE::REG> *ptr_regs_w = new std::list<LEVEL_BASE::REG>();

        for(uint32_t i=0; i<INS_MaxNumRRegs(ins); i++) {
            ptr_regs_r->push_back(INS_RegR(ins, i));
        }

        for(uint32_t i=0; i<INS_MaxNumWRegs(ins); i++) {
            ptr_regs_w->push_back(INS_RegW(ins, i));
        }

        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)regs_taint_regs,
            IARG_INST_PTR,
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_PTR, ptr_regs_r,
            IARG_PTR, ptr_regs_w,
            IARG_END);
    } else {
        if(debug) {
            *out << "4: " << disas << std::endl;
        }
    }
}

/*** SYSCALL ***/

void handle_read(CONTEXT *ctx, SYSCALL_STANDARD std) {
    ADDRINT fd = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 0)));
    start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));

    if(FDLookup.find(fd) != FDLookup.end() && FDLookup[fd].find(taintFile) != string::npos) {
#ifdef DEBUG
        ADDRINT size  = PIN_GetSyscallArgument(ctx, std, 2);
        if(debug) {
            *out << "READ of " << FDLookup[fd] << " for size 0x" << std::hex << size << " to 0x" << start << std::endl;
        }
#endif
        saveRetRead = true;
    }

}

void handle_open(CONTEXT *ctx, SYSCALL_STANDARD std) {
    fname = reinterpret_cast<char *>((PIN_GetSyscallArgument(ctx, std, 0)));
    if(debug) {
        *out << "OPEN ENTRY: " << fname << std::endl;
    }
    saveRetOpen = true;
}

void handle_mmap(CONTEXT *ctx, SYSCALL_STANDARD std) {
    ADDRINT prot = PIN_GetSyscallArgument(ctx, std, 2);
    if(debug) {
        *out << "MMAP ENTRY: " << std::hex << prot << std::endl;
    }

    if(prot & 0x4) {
        size = PIN_GetSyscallArgument(ctx, std, 1);
        saveRetMmap = true;
    }
}

VOID SyscallEntry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
    switch(PIN_GetSyscallNumber(ctx, std)) {
        case __NR_read:
            handle_read(ctx, std);
            break;
        case __NR_open:
            handle_open(ctx, std);
            break;
        case __NR_mmap:
            handle_mmap(ctx, std);
            break;
    }
}

VOID SyscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
    if (saveRetOpen){
        ADDRINT fd = PIN_GetSyscallReturn(ctx, std);
        if(debug) {
            *out << "OPEN EXIT: " << fname << " " << fd << std::endl;
        }
        FDLookup[fd] = fname;
        saveRetOpen = false;
    } else if (saveRetRead) {
        ADDRINT byteCount = PIN_GetSyscallReturn(ctx, std);
        for(UINT32 i=0; i<byteCount; i++) {
            if(debug) {
                *out << "MEMr TAINT: " << start+i << std::endl;
            }
            crash_data.taint_data_list.front()->tainted_addrs.insert(start+i);
        }

        saveRetRead = false;
    } else if(saveRetMmap) {
        ADDRINT execAddr = PIN_GetSyscallReturn(ctx, std);
        execd[execAddr] = size;
        if(debug) {
            *out << "MMAP EXEC MEM: " << std::hex << execAddr << " " << size << std::endl;
        }
        saveRetMmap = false;
    }
}

/*** FUNCTION HOOKS ***/

VOID track_free(VOID *addr) {
    if(freed.find(addr) != freed.end()) {
        if(debug) {
            *out << "OMG DOUBLE FREE" << std::endl;
        }
        return;
    }

    if(allocd.find(addr) == allocd.end()) {
        if(debug) {
            *out << "OMG FREEING UNALLOCD MEM WUT" << std::endl;
        }
        return;
    }

    SIZE size = allocd[addr];
    allocd.erase(addr);

    freed[addr] = size;

    for(int i=0; i<size; i++) {
        uint8_t *calc = (uint8_t *)addr + size;
        alloc_set.insert(calc);
        
        if(alloc_set.find(calc) != alloc_set.end()) {
            alloc_set.erase(calc);
        }
    }
}

VOID free_before(ADDRINT ip, ADDRINT retIp, ADDRINT address) {
    crash_data.pointer_free(address);

    if(debug) {
        *out << "FREE CALLED: " << reinterpret_cast<void*>(address) << " AT " << ip << std::endl;
    }
    track_free(reinterpret_cast<void*>(address));
}

VOID track_allocation(VOID *addr, SIZE size) {
    allocd[addr] = size;

    if(freed.find(addr) != freed.end()) {
        freed.erase(addr);
    }

    for(int i=0; i<size; i++) {
        uint8_t *calc = (uint8_t *)addr + size;
        alloc_set.insert(calc);
        
        if(free_set.find(calc) != free_set.end()) {
            free_set.erase(calc);
        }
    }
    // TODO: 
        // Add out of bounds for +/- 16 (or alignment) on addr
        // Check OOB on accesses
}

void *malloc_hook(CONTEXT * ctxt, AFUNPTR pf_malloc, size_t size) {
  void *res;
  PIN_CallApplicationFunction(
    ctxt, 
    PIN_ThreadId(),
    CALLINGSTD_DEFAULT, 
    pf_malloc,
    NULL,
    PIN_PARG(void *), &res, 
    PIN_PARG(size_t), size, 
    PIN_PARG_END());
  
  if(debug) {
      *out << "MALLOC CALLED: " << res << ", " << size << std::endl;
  }
  track_allocation(res, size);
  crash_data.pointer_add((ADDRINT)res, size);
  return res;  
}

VOID Image(IMG img, VOID *v)
{
    RTN mallocRtn = RTN_FindByName(img, "malloc");  
    if (RTN_Valid(mallocRtn)) {
        PROTO protoMalloc = PROTO_Allocate(
            PIN_PARG(void *), 
            CALLINGSTD_DEFAULT,
            "malloc", 
            PIN_PARG(size_t), 
            PIN_PARG_END());

        RTN_ReplaceSignature(
            mallocRtn,
            AFUNPTR(malloc_hook),
            IARG_PROTOTYPE, protoMalloc,
            IARG_CONST_CONTEXT,
            IARG_ORIG_FUNCPTR,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_END);
      }

    RTN freeRtn = RTN_FindByName(img, "free"); 
    if (RTN_Valid(freeRtn))
    {
        RTN_Open(freeRtn);
        RTN_InsertCall(
            freeRtn, 
            IPOINT_BEFORE, 
            (AFUNPTR)free_before,
            IARG_INST_PTR,
            IARG_RETURN_IP, 
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_END);
        RTN_Close(freeRtn);
    }

}

// SIGSEGV
BOOL HandleSIGSEGV(THREADID tid, INT32 sig, CONTEXT *ctx, BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v) {
    if(debug) {
        *out << PIN_ExceptionToString(pExceptInfo) << std::endl;
    }
    ADDRINT ip = PIN_GetContextReg(ctx, REG_INST_PTR);

    crash_data.signal = "SIGSEGV";
    crash_data.location = ip;

    crash_data.examine();
    crash_data.dump_info();

    return true;
}

// SIGTRAP
BOOL HandleSIGTRAP(THREADID tid, INT32 sig, CONTEXT *ctx, BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v) {
    if(debug) {
        *out << PIN_ExceptionToString(pExceptInfo) << std::endl;
    }
    ADDRINT ip = PIN_GetContextReg(ctx, REG_INST_PTR);
    
    crash_data.signal = "SIGTRAP";
    crash_data.location = ip;

    crash_data.examine();
    crash_data.dump_info();

    return true;
}

// SIGABRT
BOOL HandleSIGABRT(THREADID tid, INT32 sig, CONTEXT *ctx, BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v) {
    if(debug) {
        *out << PIN_ExceptionToString(pExceptInfo) << std::endl;
    }
    ADDRINT ip = PIN_GetContextReg(ctx, REG_INST_PTR);
    
    crash_data.signal = "SIGABRT";
    crash_data.location = ip;

    crash_data.examine();
    crash_data.dump_info();

    return true;
}

// SIGILL
BOOL HandleSIGILL(THREADID tid, INT32 sig, CONTEXT *ctx, BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v) {
    if(debug) {
        *out << PIN_ExceptionToString(pExceptInfo) << std::endl;
    }
    ADDRINT ip = PIN_GetContextReg(ctx, REG_INST_PTR);
    
    crash_data.signal = "SIGILL";
    crash_data.location = ip;

    crash_data.examine();
    crash_data.dump_info();

    return true;
}

// SIGFPE 
BOOL HandleSIGFPE(THREADID tid, INT32 sig, CONTEXT *ctx, BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v) {
    if(debug) {
        *out << PIN_ExceptionToString(pExceptInfo) << std::endl;
    }
    ADDRINT ip = PIN_GetContextReg(ctx, REG_INST_PTR);
    
    crash_data.signal = "SIGFPE";
    crash_data.location = ip;

    crash_data.examine();
    crash_data.dump_info();

    return true;
}

/*** MAIN ***/

KNOB<string> KnobOutputFile(
    KNOB_MODE_WRITEONCE,  
    "pintool",
    "o", 
    "", 
    "File name of output file");

KNOB<BOOL> KnobDebug(
    KNOB_MODE_WRITEONCE,  
    "pintool",
    "d", 
    "0", 
    "Debug prints");

KNOB<string> KnobTaintFile(
    KNOB_MODE_WRITEONCE,  
    "pintool",
    "f", 
    "__STDIN", 
    "File name of taint source");

int main(int argc, char *argv[]) {
    PIN_Init(argc, argv);
    
    FDLookup[0] = "__STDIN";
    FDLookup[1] = "__STDOUT";
    FDLookup[2] = "__STDERR";

    string fileName = KnobOutputFile.Value();
    if (!fileName.empty()) { 
        out = new std::ofstream(fileName.c_str());
        crash_data.out = out;
    }

    debug = KnobDebug.Value();
    crash_data.debug = debug;

    taintFile = KnobTaintFile.Value();

    PIN_InitSymbols();
    IMG_AddInstrumentFunction(Image, 0);
    INS_AddInstrumentFunction(Insn, 0);
    PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    PIN_AddSyscallExitFunction(SyscallExit, 0);
    
    PIN_InterceptSignal(SIGSEGV, HandleSIGSEGV, 0);
    PIN_InterceptSignal(SIGTRAP, HandleSIGTRAP, 0);
    PIN_InterceptSignal(SIGABRT, HandleSIGABRT, 0);
    PIN_InterceptSignal(SIGILL, HandleSIGILL, 0);
    PIN_InterceptSignal(SIGFPE, HandleSIGFPE, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
