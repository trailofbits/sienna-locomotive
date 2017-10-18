#include "pin.H"
#include "crash_data.h"
#include "memory_manager.h"

#ifdef __linux__
#include <sys/syscall.h>
#endif

#include <signal.h>
#include <iostream>
#include <fstream>
#include <string>
#include <list>
#include <set>
#include <map>

#ifdef _WIN32
//https://msdn.microsoft.com/en-us/library/windows/desktop/aa383751(v=vs.85).aspx
typedef const char* LPCSTR;
typedef uint32_t DWORD;
typedef void* LPVOID;
typedef void* HANDLE;
typedef struct _SECURITY_ATTRIBUTES {
	DWORD  nLength;
	LPVOID lpSecurityDescriptor;
	BOOL   bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;
#endif

CrashData crash_data;
MemoryManager *memory_manager;
string fname = "";

// syscall control
bool saveRetOpen = false;
bool saveRetRead = false;
bool saveRetMmap = false;
bool debug = false;
bool recon = false;

// mmap
ADDRINT size;
std::map<ADDRINT, ADDRINT> execd;

// files
ADDRINT start;
string taintFile = "__STDIN";
std::map<UINT64, string> FDLookup;

// malloc
std::set<UINT64> uaf_sizes;

std::ostream *out = &cout;

/*** TAINT ***/

VOID mem_taint_reg(CONTEXT *ctx, ADDRINT ip, ADDRINT mem,  UINT32 size) {
    crash_data.mem_to_reg(ctx, ip, memory_manager, mem, size);
}

VOID regs_taint_mem(CONTEXT *ctx, ADDRINT ip, ADDRINT mem, UINT32 size) {
    crash_data.regs_to_mem(ctx, ip, memory_manager, mem, size);
}

VOID regs_taint_regs(CONTEXT *ctx, ADDRINT ip) {
    crash_data.regs_to_regs(ctx, ip, memory_manager);
}

VOID handle_indirect(ADDRINT ip, LEVEL_BASE::REG reg, ADDRINT regval, BOOL isRet) {
    crash_data.taint_indirect(ip, memory_manager, reg, regval, execd, isRet);
}

VOID wrap_reg_untaint(ADDRINT ip, LEVEL_BASE::REG reg) {
    if(debug) {
        *out << "UT: " << ip << " " << *memory_manager->disas[ip] << std::endl << std::flush;
    }

    std::list<TaintData*>::iterator taint_it;
    for(taint_it = crash_data.taint_data_list.begin(); taint_it != crash_data.taint_data_list.end(); taint_it++) {
        TaintData *ptr_taint_data = *taint_it;
        ptr_taint_data->reg_untaint(ip, memory_manager, reg);
    }
}

VOID handle_xchg(ADDRINT ip, LEVEL_BASE::REG reg_a, LEVEL_BASE::REG reg_b) {
    if(debug) {
        *out << ip << " " << *memory_manager->disas[ip] << std::endl << std::flush;
    }

    std::list<TaintData*>::iterator taint_it;
    for(taint_it = crash_data.taint_data_list.begin(); taint_it != crash_data.taint_data_list.end(); taint_it++) {
        TaintData *ptr_taint_data = *taint_it;
        BOOL tainted_a = ptr_taint_data->reg_is_tainted(reg_a);
        BOOL tainted_b = ptr_taint_data->reg_is_tainted(reg_b);
        if(tainted_a ^ tainted_b) {
            if(tainted_a) {
                ptr_taint_data->reg_untaint(ip, memory_manager, reg_a);
                ptr_taint_data->reg_taint(ip, memory_manager, reg_b);
            } else {
                ptr_taint_data->reg_taint(ip, memory_manager, reg_a);
                ptr_taint_data->reg_untaint(ip, memory_manager, reg_b);
            }
       } 
    }
}

/*** INSTRUCTION ***/

VOID record(ADDRINT ip) {
    // *out << std::hex << ip << " " << *memory_manager.disas[ip] << std::endl << std::flush;
	crash_data.last_addrs_head = (crash_data.last_addrs_head + 1) % RECORD_COUNT;
    crash_data.last_addrs[crash_data.last_addrs_head] = ip;

    crash_data.insns[ip].clear_flags();
}

VOID record_call(ADDRINT target, ADDRINT loc) {
	crash_data.last_calls_head = (crash_data.last_calls_head + 1) % RECORD_COUNT;
	crash_data.last_calls[crash_data.last_calls_head] = target;
}

BOOL handle_specific(INS ins) {
    OPCODE opcode = INS_Opcode(ins);

    // NOP
    if(opcode == 0x1c7) {
        // skip
        return true;
    }

    // indirect jump, indirect call
    if(INS_IsIndirectBranchOrCall(ins) && INS_MaxNumRRegs(ins) > 0) {
        if(debug) {
            *out << "INDIRECT: " << REG_StringShort(INS_RegR(ins, 0)) << std::endl << std::flush;
        }

        INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)handle_indirect,
                IARG_INST_PTR,
                IARG_UINT32, INS_RegR(ins, 0),
                IARG_REG_VALUE, INS_RegR(ins, 0),
                IARG_BOOL, INS_IsRet(ins),
                IARG_END);
        return true;
    }

    // POP
    if(opcode == 0x249) {
        memory_manager->add_regs_rw_pop(ins);

        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)mem_taint_reg,
            IARG_CONTEXT,
            IARG_INST_PTR,
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
                IARG_UINT32, INS_RegR(ins, 0),
                IARG_END);
            return true;
        } 

        return false; 
    }

    // XCHG
    if(opcode == 0x5e0) {
        if(INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)) {
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)handle_xchg,
                IARG_INST_PTR,
                IARG_UINT32, INS_RegR(ins, 0),
                IARG_UINT32, INS_RegR(ins, 1),
                IARG_END);
        }
        return true;
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

int regd_count = 0;

VOID reg_dump_32(ADDRINT eax, ADDRINT ecx, ADDRINT edx, ADDRINT ebx, 
    ADDRINT esp, ADDRINT ebp, ADDRINT esi, ADDRINT edi, ADDRINT eip)
{
    *out << "eax\t" << std::hex << eax << std::endl << std::flush;
    *out << "ecx\t" << std::hex << ecx << std::endl << std::flush;
    *out << "edx\t" << std::hex << edx << std::endl << std::flush;
    *out << "ebx\t" << std::hex << ebx << std::endl << std::flush;
    *out << "esp\t" << std::hex << esp << std::endl << std::flush;
    *out << "ebp\t" << std::hex << ebp << std::endl << std::flush;
    *out << "esi\t" << std::hex << esi << std::endl << std::flush;
    *out << "edi\t" << std::hex << edi << std::endl << std::flush;
    *out << "eip\t" << std::hex << eip << std::endl << std::flush;
}

/*  
    INS_InsertCall(ins,
        IPOINT_BEFORE, (AFUNPTR)reg_dump_32,
        IARG_REG_VALUE, LEVEL_BASE::REG_EAX,
        IARG_REG_VALUE, LEVEL_BASE::REG_ECX,
        IARG_REG_VALUE, LEVEL_BASE::REG_EDX,
        IARG_REG_VALUE, LEVEL_BASE::REG_EBX,
        IARG_REG_VALUE, LEVEL_BASE::REG_ESP,
        IARG_REG_VALUE, LEVEL_BASE::REG_EBP,
        IARG_REG_VALUE, LEVEL_BASE::REG_ESI,
        IARG_REG_VALUE, LEVEL_BASE::REG_EDI,
        IARG_REG_VALUE, LEVEL_BASE::REG_EIP,
        IARG_END);
*/

VOID reg_dump_64(ADDRINT rax, ADDRINT rcx, ADDRINT rdx, ADDRINT rbx, 
    ADDRINT rsp, ADDRINT rbp, ADDRINT rsi, ADDRINT rdi, ADDRINT rip,
    ADDRINT r8, ADDRINT r9, ADDRINT r10, ADDRINT r11, 
    ADDRINT r12, ADDRINT r13, ADDRINT r14, ADDRINT r15)
{
    *out << "rax\t" << std::hex << rax << std::endl << std::flush;
    *out << "rcx\t" << std::hex << rcx << std::endl << std::flush;
    *out << "rdx\t" << std::hex << rdx << std::endl << std::flush;
    *out << "rbx\t" << std::hex << rbx << std::endl << std::flush;
    *out << "rsp\t" << std::hex << rsp << std::endl << std::flush;
    *out << "rbp\t" << std::hex << rbp << std::endl << std::flush;
    *out << "rsi\t" << std::hex << rsi << std::endl << std::flush;
    *out << "rdi\t" << std::hex << rdi << std::endl << std::flush;
    *out << "rip\t" << std::hex << rip << std::endl << std::flush;
    *out << "r8\t" << std::hex << r8 << std::endl << std::flush;
    *out << "r9\t" << std::hex << r9 << std::endl << std::flush;
    *out << "r10\t" << std::hex << r10 << std::endl << std::flush;
    *out << "r11\t" << std::hex << r11 << std::endl << std::flush;
    *out << "r12\t" << std::hex << r12 << std::endl << std::flush;
    *out << "r13\t" << std::hex << r13 << std::endl << std::flush;
    *out << "r14\t" << std::hex << r14 << std::endl << std::flush;
    *out << "r15\t" << std::hex << r15 << std::endl << std::flush;
}

/*
    INS_InsertCall(ins,
        IPOINT_BEFORE, (AFUNPTR)reg_dump_64,
        IARG_REG_VALUE, LEVEL_BASE::REG_RAX,
        IARG_REG_VALUE, LEVEL_BASE::REG_RCX,
        IARG_REG_VALUE, LEVEL_BASE::REG_RDX,
        IARG_REG_VALUE, LEVEL_BASE::REG_RBX,
        IARG_REG_VALUE, LEVEL_BASE::REG_RSP,
        IARG_REG_VALUE, LEVEL_BASE::REG_RBP,
        IARG_REG_VALUE, LEVEL_BASE::REG_RSI,
        IARG_REG_VALUE, LEVEL_BASE::REG_RDI,
        IARG_REG_VALUE, LEVEL_BASE::REG_RIP,
        IARG_REG_VALUE, LEVEL_BASE::REG_R8,
        IARG_REG_VALUE, LEVEL_BASE::REG_R9,
        IARG_REG_VALUE, LEVEL_BASE::REG_R10,
        IARG_REG_VALUE, LEVEL_BASE::REG_R11,
        IARG_REG_VALUE, LEVEL_BASE::REG_R12,
        IARG_REG_VALUE, LEVEL_BASE::REG_R13,
        IARG_REG_VALUE, LEVEL_BASE::REG_R14,
        IARG_REG_VALUE, LEVEL_BASE::REG_R15,
        IARG_END);
*/

VOID Insn(INS ins, VOID *v) {
    string disas = INS_Disassemble(ins);
    ADDRINT ip = INS_Address(ins);
    memory_manager->add_disas(ins);

    // std::cout << "OPCODE: (" << std::hex << ip << ") " << disas << " : " << std::hex << INS_Opcode(ins) << std::endl << std::flush; 

    if(!crash_data.insns.count(ip)) {
        Instruction insn(ip, disas);
        crash_data.insns[ip] = insn;
    } 
    
    INS_InsertCall(ins, 
        IPOINT_BEFORE, (AFUNPTR)record,
        IARG_ADDRINT, ip,
        IARG_CALL_ORDER, CALL_ORDER_FIRST,
        IARG_END);
    
    if(handle_specific(ins)) {
        return;
    }
	
    if(INS_OperandCount(ins) < 2) {
        if(debug) {
            *out << "5: " << disas << std::endl << std::flush;
        }
        return;
    }

    if(INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
        memory_manager->add_regs_rw(ins);

        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)mem_taint_reg,
            IARG_CONTEXT,
            IARG_INST_PTR,
            IARG_MEMORYOP_EA, 0,
            IARG_UINT32, (UINT32)INS_MemoryReadSize(ins),
            IARG_END);
        

    } else if(INS_MemoryOperandIsWritten(ins, 0)) {
        memory_manager->add_regs_r(ins);
        
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)regs_taint_mem,
            IARG_CONTEXT,
            IARG_INST_PTR,
            IARG_MEMORYOP_EA, 0,
            IARG_MEMORYWRITE_SIZE,
            IARG_END);

    } else if(INS_OperandIsReg(ins, 0)) {
        memory_manager->add_regs_rw(ins);

        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)regs_taint_regs,
            IARG_CONTEXT,
            IARG_INST_PTR,
            IARG_END);
    } else {
        if(debug) {
            *out << "4: " << disas << std::endl << std::flush;
        }
    }
}

/*** SYSCALL ***/

void handle_read(CONTEXT *ctx, SYSCALL_STANDARD std) {
    ADDRINT fd = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 0)));
    start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));

    if(FDLookup.find(fd) != FDLookup.end() && FDLookup[fd].find(taintFile) != string::npos) {
        if(debug) {
            ADDRINT size  = PIN_GetSyscallArgument(ctx, std, 2);
            *out << "READ of " << FDLookup[fd] << " for size 0x" << std::hex << size << " to 0x" << start << std::endl << std::flush;
        }
        saveRetRead = true;
    }

}

void handle_open(CONTEXT *ctx, SYSCALL_STANDARD std) {
    fname = reinterpret_cast<char *>((PIN_GetSyscallArgument(ctx, std, 0)));
    if(debug) {
        *out << "OPEN ENTRY: " << fname << std::endl << std::flush;
    }
    saveRetOpen = true;
}

void handle_mmap(CONTEXT *ctx, SYSCALL_STANDARD std) {
    ADDRINT prot = PIN_GetSyscallArgument(ctx, std, 2);
    if(debug) {
        *out << "MMAP ENTRY: " << std::hex << prot << std::endl << std::flush;
    }

    if(prot & 0x4) {
        size = PIN_GetSyscallArgument(ctx, std, 1);
        saveRetMmap = true;
    }
}

VOID SyscallEntry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
	if (recon) {
		*out << "SYSCALL NUMBER: " << (PIN_GetSyscallNumber(ctx, std) & 0xFF) << std::endl << std::flush;
	}

	switch(PIN_GetSyscallNumber(ctx, std) & 0xFF) {
        case 6:
            handle_read(ctx, std);
            break;
        case 85:
            handle_open(ctx, std);
            break;
        /*case __NR_mmap:
            handle_mmap(ctx, std);
            break;*/
    }//*/
}

VOID SyscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
    if (saveRetOpen){
        ADDRINT fd = PIN_GetSyscallReturn(ctx, std);
        if(debug) {
            *out << "OPEN EXIT: " << fname << " " << fd << std::endl << std::flush;
        }
        FDLookup[fd] = fname;
        saveRetOpen = false;
    } else if (saveRetRead) {
        ADDRINT byteCount = PIN_GetSyscallReturn(ctx, std);
        if(debug) {
            *out << "MEMr TAINT: " << start << ": " << byteCount << std::endl << std::flush;
        }
        
        if(byteCount+1 > byteCount) {
            for(UINT32 i=0; i<byteCount; i++) {
                crash_data.taint_data_list.front()->tainted_addrs.insert(start+i);
            }
        }

        saveRetRead = false;
    } else if(saveRetMmap) {
        ADDRINT execAddr = PIN_GetSyscallReturn(ctx, std);
        execd[execAddr] = size;
        if(debug) {
            *out << "MMAP EXEC MEM: " << std::hex << execAddr << " " << size << std::endl << std::flush;
        }
        saveRetMmap = false;
    }
}

/*** FUNCTION HOOKS ***/

VOID track_free(ADDRINT addr) {
	if(crash_data.alloc_info_map.count(addr) == 0) {
        if(debug) {
            *out << "FREEING UNALLOCD OR UNTRACKED MEM" << std::endl << std::flush;
        }
        return;
    }

    if(crash_data.alloc_info_map[addr].back().free) {
        if(debug) {
            *out << "POSSIBLE DOUBLE FREE" << std::endl << std::flush;
        }
        return;
    }

    crash_data.alloc_info_map[addr].back().free = true;
}

VOID free_before(ADDRINT ip, ADDRINT retIp, ADDRINT address) {
    crash_data.pointer_free(address);

    if(debug) {
        *out << "FREE CALLED: " << reinterpret_cast<void*>(address) << " AT " << ip << std::endl << std::flush;
    }
    track_free(address);
}

VOID track_allocation(VOID *addr, SIZE size) {
    if(size > 0x7fffffff) { // (2 << 30) - 1 
        if(debug) {
            *out << "ALLOC SIZE TOO LARGE, NOT TRACKING" << std::endl << std::flush;
        }
        return;
    }

    struct AllocInfo alloc_info;
    alloc_info.size = size;
    alloc_info.free = false;
    crash_data.alloc_info_map[(ADDRINT)addr].push_back(alloc_info);
    for(int i = 0; i < size; i++) {
        crash_data.alloc_addr_map[(ADDRINT)addr+i].insert((ADDRINT)addr);
    }
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
      *out << "MALLOC CALLED: " << res << ", " << size << std::endl << std::flush;
    }

	track_allocation(res, size);

    if(uaf_sizes.count(size)) {
        crash_data.pointer_add((ADDRINT)res, size);
    }

    return res;  
}

FILE * fopen_hook(CONTEXT * ctxt, AFUNPTR pf_fopen, const char *fname, const char *mode) {
	FILE *res;
	//*out << "FOPEN CALLED " << fname << std::endl << std::flush;
	PIN_CallApplicationFunction(
		ctxt,
		PIN_ThreadId(),
		CALLINGSTD_DEFAULT,
		pf_fopen,
		NULL,
		PIN_PARG(int), &res,
		PIN_PARG(const char *), fname,
		PIN_PARG(const char *), mode,
		PIN_PARG_END());

	if (debug) {
		*out << "FOPEN CALLED: " << fname << " (" << res << ")" << std::endl << std::flush;
	}

	//FDLookup[res] = fname;

	return res;
}

HANDLE cf_hook(CONTEXT * ctxt, AFUNPTR pf_cf,
		LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
		LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
		DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	HANDLE res;
	//*out << "CREATEFILE CALLED " << fname << std::endl << std::flush;
	PIN_CallApplicationFunction(
		ctxt,
		PIN_ThreadId(),
		CALLINGSTD_DEFAULT,
		pf_cf,
		NULL,
		PIN_PARG(HANDLE), &res,
		PIN_PARG(LPCSTR), lpFileName,
		PIN_PARG(DWORD), dwDesiredAccess,
		PIN_PARG(DWORD), dwShareMode,
		PIN_PARG(LPSECURITY_ATTRIBUTES), lpSecurityAttributes,
		PIN_PARG(DWORD), dwCreationDisposition,
		PIN_PARG(DWORD), dwFlagsAndAttributes,
		PIN_PARG(HANDLE), hTemplateFile,
		PIN_PARG_END());

	//FDLookup[res] = fname;

	return res;
}

VOID Image(IMG img, VOID *v)
{
    RTN mallocRtn = RTN_FindByName(img, "malloc");  
    if (RTN_Valid(mallocRtn)){ 
        PROTO protoMalloc = PROTO_Allocate(
            PIN_PARG(VOID *), 
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

//#ifndef __linux__
//	RTN cfRtn = RTN_FindByName(img, "CreateFileW");
//	if (RTN_Valid(cfRtn)) {
//		PROTO protoCF = PROTO_Allocate(
//			PIN_PARG(HANDLE),
//			CALLINGSTD_DEFAULT,
//			"CreateFileW",
//			PIN_PARG(LPCSTR),
//			PIN_PARG(DWORD),
//			PIN_PARG(DWORD),
//			PIN_PARG(LPSECURITY_ATTRIBUTES),
//			PIN_PARG(DWORD),
//			PIN_PARG(DWORD),
//			PIN_PARG(HANDLE),
//			PIN_PARG_END());
//
//		RTN_ReplaceSignature(
//			cfRtn,
//			AFUNPTR(cf_hook),
//			IARG_PROTOTYPE, protoCF,
//			IARG_CONST_CONTEXT,
//			IARG_ORIG_FUNCPTR,
//			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
//			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
//			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
//			IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
//			IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
//			IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
//			IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
//			IARG_END);
//	}
//
//	RTN fopenRtn = RTN_FindByName(img, "fopen");
//	if (RTN_Valid(fopenRtn)) {
//		PROTO protoFopen = PROTO_Allocate(
//			PIN_PARG(INT),
//			CALLINGSTD_DEFAULT,
//			"fopen",
//			PIN_PARG(const char *),
//			PIN_PARG(const char *),
//			PIN_PARG_END());
//
//		RTN_ReplaceSignature(
//			fopenRtn,
//			AFUNPTR(fopen_hook),
//			IARG_PROTOTYPE, protoFopen,
//			IARG_CONST_CONTEXT,
//			IARG_ORIG_FUNCPTR,
//			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
//			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
//			IARG_END);
//	}
//#endif
}

// SIGSEGV
BOOL HandleSIGSEGV(THREADID tid, INT32 sig, CONTEXT *ctx, BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v) {
    if(debug) {
        *out << PIN_ExceptionToString(pExceptInfo) << std::endl << std::flush;
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
        *out << PIN_ExceptionToString(pExceptInfo) << std::endl << std::flush;
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
        *out << PIN_ExceptionToString(pExceptInfo) << std::endl << std::flush;
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
        *out << PIN_ExceptionToString(pExceptInfo) << std::endl << std::flush;
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
        *out << PIN_ExceptionToString(pExceptInfo) << std::endl << std::flush;
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

KNOB<BOOL> KnobRecon(
	KNOB_MODE_WRITEONCE,
	"pintool",
	"r",
	"0",
	"Print syscall numbers");

KNOB<string> KnobTaintFile(
    KNOB_MODE_WRITEONCE,  
    "pintool",
    "f", 
    "__STDIN", 
    "File name of taint source");

KNOB<UINT64> KnobUAF(
    KNOB_MODE_APPEND,  
    "pintool",
    "uaf", 
    "", 
    "Use after free detection");

VOID Fini(INT32 code, VOID *v)
{
	*out << "===============================================" << std::endl;
	*out << "ANALYSIS COMPLETE" << std::endl;
	*out << "===============================================" << std::endl;
}

int main(int argc, char *argv[]) {
    memory_manager = new MemoryManager();

    PIN_Init(argc, argv);
    
    FDLookup[0] = "__STDIN";
    FDLookup[1] = "__STDOUT";
    FDLookup[2] = "__STDERR";

    string fileName = KnobOutputFile.Value();
    if (!fileName.empty()) { 
        out = new std::ofstream(fileName.c_str());
        crash_data.out = out;
		crash_data.taint_data_list.front()->out = out;
    }

    debug = KnobDebug.Value();
	recon = KnobRecon.Value();
    crash_data.debug = debug;
	crash_data.taint_data_list.front()->debug = debug;

    taintFile = KnobTaintFile.Value();
	*out << "init" << std::endl << std::flush;
    PIN_InitSymbols();
    INS_AddInstrumentFunction(Insn, 0);

//#ifdef __linux__
    PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    PIN_AddSyscallExitFunction(SyscallExit, 0);
//#endif
    
   // IMG_AddInstrumentFunction(Image, 0);

    for(UINT32 i = 0; i < KnobUAF.NumberOfValues(); i++) {
        uaf_sizes.insert(KnobUAF.Value(i));
    }
    
    PIN_InterceptSignal(SIGSEGV, HandleSIGSEGV, 0);
    PIN_InterceptSignal(SIGTRAP, HandleSIGTRAP, 0);
    PIN_InterceptSignal(SIGABRT, HandleSIGABRT, 0);
    PIN_InterceptSignal(SIGILL, HandleSIGILL, 0);
    PIN_InterceptSignal(SIGFPE, HandleSIGFPE, 0);

	PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
