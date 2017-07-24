#include "pin.H"
#include <sys/syscall.h>
#include <signal.h>
#include <iostream>
#include <fstream>
#include <string>
#include <list>
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

#define RECORD_COUNT 5
std::list<ADDRINT> last_addrs;
std::list<ADDRINT> last_calls;

std::map<VOID *, SIZE> allocd;
std::map<VOID *, SIZE> freed;
std::set<VOID *> alloc_set;
std::set<VOID *> free_set;

std::ostream *out = &cerr;

/*** TAINT ***/

VOID propagate_taint(CONTEXT *ctx) {
    return;
}

bool reg_is_tainted(LEVEL_BASE::REG reg) {
    REG fullReg = REG_FullRegName(reg);
    bool tainted = tainted_regs.find(fullReg) != tainted_regs.end();

    return tainted;
}

VOID reg_taint(ADDRINT ip, std::string *ptr_disas, LEVEL_BASE::REG reg) {
    *out << std::hex << ip << ": " << *ptr_disas << std::endl;
    REG fullReg = REG_FullRegName(reg);
    *out << "REG TAINT: " << REG_StringShort(reg) << std::endl;
    tainted_regs.insert(fullReg);
}

VOID reg_untaint(ADDRINT ip, std::string *ptr_disas, LEVEL_BASE::REG reg) {
    *out << std::hex << ip << ": " << *ptr_disas << std::endl;
    REG fullReg = REG_FullRegName(reg);
    *out << "REG UNTAINT: " << REG_StringShort(reg) << std::endl;
    std::set<LEVEL_BASE::REG>::iterator it = tainted_regs.find(fullReg);
    if(it != tainted_regs.end()) {
        tainted_regs.erase(it);
    }
}

bool mem_is_tainted(ADDRINT mem) {
    bool tainted = tainted_addrs.find(mem) != tainted_addrs.end();
    return tainted;
}

VOID mem_untaint(ADDRINT ip, std::string *ptr_disas, ADDRINT mem, UINT32 size) {
    *out << std::hex << ip << ": " << *ptr_disas << std::endl;

    *out << "TAINTED REGS:" << std::endl;
    std::set<LEVEL_BASE::REG>::iterator sit;
    for(sit=tainted_regs.begin(); sit != tainted_regs.end(); sit++) {
        *out << REG_StringShort(*sit) << std::endl;
    }
    
    for(UINT32 i=0; i<size; i++) {
        std::set<ADDRINT>::iterator it = tainted_addrs.find(mem+i);   
        *out << "MEM UNTAINT: " << mem+i << std::endl;
        if(it != tainted_addrs.end()) {
            tainted_addrs.erase(it);
        }
    }
}

VOID mem_taint(ADDRINT ip, std::string *ptr_disas, ADDRINT mem, UINT32 size) {
    *out << std::hex << ip << ": " << *ptr_disas << std::endl;
    for(UINT32 i=0; i<size; i++) {
        *out << "MEM TAINT: " << mem+i << std::endl;
        tainted_addrs.insert(mem+i);
    }
}

VOID mem_taint_reg(ADDRINT ip, std::string *ptr_disas, REG reg, ADDRINT mem,  UINT32 size) {
    *out << std::hex << ip << ": " << *ptr_disas << std::endl;

    bool tainted = false;
    for(UINT32 i=0; i<size; i++) {
        if(mem_is_tainted(mem+i)) {
            tainted = true;
            break;
        }
    }

    if(tainted) {
        *out << "REGm TAINT: " << REG_StringShort(reg) << std::endl;
        REG fullReg = REG_FullRegName(reg);
        tainted_regs.insert(fullReg);

        *out << "TAINTED REGS:" << std::endl;
        std::set<LEVEL_BASE::REG>::iterator sit;
        for(sit=tainted_regs.begin(); sit != tainted_regs.end(); sit++) {
            *out << REG_StringShort(*sit) << std::endl;
        }
        
    } else {
        *out << "REGm UNTAINT: " << REG_StringShort(reg) << std::endl;
        REG fullReg = REG_FullRegName(reg);
        std::set<LEVEL_BASE::REG>::iterator it = tainted_regs.find(fullReg);
        if(it != tainted_regs.end()) {
            tainted_regs.erase(it);
        }
    }
}

VOID regs_taint_mem(ADDRINT ip, std::string *ptr_disas, std::list<LEVEL_BASE::REG> *ptr_regs, ADDRINT mem, UINT32 size) {
    std::list<LEVEL_BASE::REG>::iterator it;
    bool tainted = false;

    for(it = ptr_regs->begin(); it != ptr_regs->end(); it++) {
        tainted |= reg_is_tainted(*it);
    }

    if(tainted) {
        mem_taint(ip, ptr_disas, mem, size);
    } else {
        mem_untaint(ip, ptr_disas, mem, size);
    }
}

VOID regs_taint_regs(ADDRINT ip, std::string *ptr_disas, 
        std::list<LEVEL_BASE::REG> *ptr_regs_r, std::list<LEVEL_BASE::REG> *ptr_regs_w) {
    std::list<LEVEL_BASE::REG>::iterator it;
    bool tainted = false;

    for(it = ptr_regs_r->begin(); it != ptr_regs_r->end(); it++) {
        tainted |= reg_is_tainted(*it);
    }

    for(it=ptr_regs_w->begin(); it != ptr_regs_w->end(); it++) {
        if(tainted) {
            reg_taint(ip, ptr_disas, *it);
        } else {
            reg_untaint(ip, ptr_disas, *it);
        }
    }
}

/*** INSTRUCTION ***/

VOID record(INS ins) {
    last_addrs.push_back(INS_Address(ins));
    while(last_addrs.size() > RECORD_COUNT) {
        last_addrs.pop_front();
    }
}

VOID record_call(ADDRINT target, ADDRINT loc) {
    last_calls.push_back(target);
    while(last_calls.size() > RECORD_COUNT) {
        last_calls.pop_front();
    }
}

VOID handle_specific(INS ins) {
    if(INS_IsCall(ins) && INS_IsDirectBranchOrCall(ins)) {
        INS_InsertCall(ins, 
            IPOINT_BEFORE, 
            (AFUNPTR)record_call, 
            IARG_ADDRINT, INS_DirectBranchOrCallTargetAddress(ins),
            IARG_ADDRINT, INS_Address(ins),
            IARG_END);
    } 
}

VOID Insn(INS ins, VOID *v) {
    // pass address, disassembled insn to all insert calls
    record(ins);
    handle_specific(ins);
    string disas = INS_Disassemble(ins);
    *out << "x " << disas << std::endl;
    /*
        Special cases
            xor reg, reg -> clear taint
            indirect branches and calls
            push
            pop
    */

    if(INS_OperandCount(ins) < 2) {
        *out << "5: " << disas << std::endl;
        return;
    }

    if(INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
        for(uint32_t i=0; i<INS_MaxNumWRegs(ins); i++) {
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)mem_taint_reg,
                IARG_INST_PTR,
                IARG_PTR, new std::string(INS_Disassemble(ins)),
                IARG_UINT32, INS_RegW(ins, i),
                IARG_MEMORYOP_EA, 0,
                IARG_UINT32, (UINT32)INS_MemoryReadSize(ins),
                IARG_END);
        }
    } else if(INS_MemoryOperandIsWritten(ins, 0)) {
        *out << "xTAINTED REGS:" << std::endl;
        std::set<LEVEL_BASE::REG>::iterator sit;
        for(sit=tainted_regs.begin(); sit != tainted_regs.end(); sit++) {
            *out << REG_StringShort(*sit) << std::endl;
        }

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
        *out << "4: " << disas << std::endl;
    }
}

/*** SYSCALL ***/

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
    *out << "OPEN ENTRY: " << fname << std::endl;
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
        *out << "OPEN EXIT: " << fname << " " << fd << std::endl;
        FDLookup[fd] = fname;
        saveRetOpen = false;
    } else if (saveRetRead) {
        unsigned long byteCount = PIN_GetSyscallReturn(ctx, std);
        for(UINT32 i=0; i<byteCount; i++) {
            *out << "MEM TAINT: " << start+i << std::endl;
            tainted_addrs.insert(start+i);
        }

        saveRetRead = false;
    }
}

/*** FUNCTION HOOKS ***/

VOID track_free(VOID *addr) {
    if(freed.find(addr) != freed.end()) {
        *out << "OMG DOUBLE FREE" << std::endl;
        return;
    }

    if(allocd.find(addr) == allocd.end()) {
        *out << "OMG FREEING UNALLOCD MEM WUT" << std::endl;
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

VOID free_before(ADDRINT retIp, ADDRINT address) {
    *out << "FREE CALLED: " << reinterpret_cast<void*>(address) << std::endl;
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
  
  *out << "MALLOC CALLED: " << res << ", " << size << std::endl;
  track_allocation(res, size);
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
            IARG_RETURN_IP, 
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_END);
        RTN_Close(freeRtn);
    }

}

/*** CRASH ANALYSIS ***/

BOOL HandleSignal(THREADID tid, INT32 sig, CONTEXT *ctx, BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v) {
    ADDRINT ip = PIN_GetContextReg(ctx, REG_INST_PTR);
    *out << "S E G F A U L T " << std::endl;
    *out << "AT: " << std::hex << ip << std::endl << std::endl;

    std::set<LEVEL_BASE::REG>::iterator sit;
    *out << "TAINTED REGS:" << std::endl;
    for(sit=tainted_regs.begin(); sit != tainted_regs.end(); sit++) {
        *out << REG_StringShort(*sit) << std::endl;
    }
    *out << std::endl;

    *out << "LAST " << RECORD_COUNT << " ADDRESSES: " << std::endl;
    std::list<ADDRINT>::iterator lit;
    for(lit=last_addrs.begin(); lit != last_addrs.end(); lit++) {
        *out << *lit << std::endl;
    }
    *out << std::endl;

    *out << "LAST " << RECORD_COUNT << " CALLS: " << std::endl;
    for(lit=last_calls.begin(); lit != last_calls.end(); lit++) {
        *out << *lit << std::endl;
    }
    *out << std::endl;

    return true;
}

/*** MAIN ***/

VOID Fini(INT32 code, VOID *v)
{
    *out <<  "===============================================" << endl;
}

VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v) {
    threadCount++;
}

KNOB<string> KnobTaintFile(
    KNOB_MODE_WRITEONCE,  
    "pintool",
    "f", 
    "__STDIN", 
    "File name of taint source.");

int main(int argc, char *argv[]) {
    PIN_Init(argc, argv);
    
    FDLookup[0] = "__STDIN";
    FDLookup[1] = "__STDOUT";
    FDLookup[2] = "__STDERR";

    string fileName = "out.txt";
    if (!fileName.empty()) { 
        out = new std::ofstream(fileName.c_str());
    }

    taintFile = KnobTaintFile.Value();
    std::cout << "TAINT FILE" << std::endl;
    std::cout << taintFile << std::endl;


    PIN_InitSymbols();
    IMG_AddInstrumentFunction(Image, 0);
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
