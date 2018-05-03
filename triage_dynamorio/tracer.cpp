#define EVENT_APP event_app_bb
// #define EVENT_APP event_app_instruction

#define EVENT_THREAD_EXIT event_thread_exit_cov
// #define EVENT_THREAD_EXIT event_thread_exit

#include <stdio.h>
#include <stddef.h> /* for offsetof */
#include <map>
#include <set>

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drwrap.h"
#include "dr_ir_instr.h"
#include "droption.h"

extern "C" {
#include "utils.h"
}

#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

#include <Dbghelp.h>
#include <Windows.h>
#include <winsock2.h>
#include <winhttp.h>

void *mutatex;
bool replay;
bool mutate_count;
UINT64 run_id;

std::set<reg_id_t> tainted_regs;
std::set<app_pc> tainted_mems;

static droption_t<std::string> op_target(
    DROPTION_SCOPE_CLIENT, 
    "t", 
    "", 
    "target",
    "Specific call to target.");

static droption_t<std::string> op_include(
    DROPTION_SCOPE_CLIENT, 
    "i", 
    "", 
    "include",
    "Functions to be included in hooking.");

static droption_t<unsigned int> op_no_taint(
    DROPTION_SCOPE_CLIENT, 
    "nt", 
    0, 
    "no-taint",
    "Do not do instruction level instrumentation.");

enum class Function {
    ReadFile,
    recv,
    WinHttpReadData,
    InternetReadFile,
    WinHttpWebSocketReceive,
    RegQueryValueEx,
    ReadEventLog,
};

std::map<Function, UINT64> call_counts;

char *get_function_name(Function function) {
    switch(function) {
        case Function::ReadFile:
            return ",ReadFile";
        case Function::recv:
            return ",recv";
        case Function::WinHttpReadData:
            return ",WinHttpReadData";
        case Function::InternetReadFile:
            return ",InternetReadFile";
        case Function::WinHttpWebSocketReceive:
            return ",WinHttpWebSocketReceive";
        case Function::RegQueryValueEx:
            return ",RegQueryValueEx";
        case Function::ReadEventLog:
            return ",ReadEventLog";
    }

    return "unknown";
}

static reg_id_t reg_to_full_width32(reg_id_t reg) {
    switch(reg){
        case DR_REG_AX:
        case DR_REG_AH:
        case DR_REG_AL:
            return DR_REG_EAX;
        case DR_REG_BX:
        case DR_REG_BH:
        case DR_REG_BL:
            return DR_REG_EBX;
        case DR_REG_CX:
        case DR_REG_CH:
        case DR_REG_CL:
            return DR_REG_ECX;
        case DR_REG_DX:
        case DR_REG_DH:
        case DR_REG_DL:
            return DR_REG_EDX;
        case DR_REG_SP:
            return DR_REG_ESP;
        case DR_REG_BP:
            return DR_REG_EBP;
        case DR_REG_SI:
            return DR_REG_ESI;
        case DR_REG_DI:
            return DR_REG_EDI;
        default:
            return reg;
    }
}

static reg_id_t reg_to_full_width64(reg_id_t reg) {
    switch(reg){
        case DR_REG_EAX:
        case DR_REG_AX:
        case DR_REG_AH:
        case DR_REG_AL:
            return DR_REG_RAX;
        case DR_REG_EBX:
        case DR_REG_BX:
        case DR_REG_BH:
        case DR_REG_BL:
            return DR_REG_RBX;
        case DR_REG_ECX:
        case DR_REG_CX:
        case DR_REG_CH:
        case DR_REG_CL:
            return DR_REG_RCX;
        case DR_REG_EDX:
        case DR_REG_DX:
        case DR_REG_DH:
        case DR_REG_DL:
            return DR_REG_RDX;
        case DR_REG_R8D:
        case DR_REG_R8W:
        case DR_REG_R8L:
            return DR_REG_R8;
        case DR_REG_R9D:
        case DR_REG_R9W:
        case DR_REG_R9L:
            return DR_REG_R9;
        case DR_REG_R10D:
        case DR_REG_R10W:
        case DR_REG_R10L:
            return DR_REG_R10;
        case DR_REG_R11D:
        case DR_REG_R11W:
        case DR_REG_R11L:
            return DR_REG_R11;
        case DR_REG_R12D:
        case DR_REG_R12W:
        case DR_REG_R12L:
            return DR_REG_R12;
        case DR_REG_R13D:
        case DR_REG_R13W:
        case DR_REG_R13L:
            return DR_REG_R13;
        case DR_REG_R14D:
        case DR_REG_R14W:
        case DR_REG_R14L:
            return DR_REG_R14;
        case DR_REG_R15D:
        case DR_REG_R15W:
        case DR_REG_R15L:
            return DR_REG_R15;
        case DR_REG_ESP:
        case DR_REG_SP:
            return DR_REG_RSP;
        case DR_REG_EBP:
        case DR_REG_BP:
            return DR_REG_RBP;
        case DR_REG_ESI:
        case DR_REG_SI:
            return DR_REG_RSI;
        case DR_REG_EDI:
        case DR_REG_DI:
            return DR_REG_RDI;
        default:
            return reg;
    }
}

static bool
is_tainted(void *drcontext, opnd_t opnd) 
{
    if(opnd_is_reg(opnd)) {
        reg_id_t reg = opnd_get_reg(opnd);
        reg = reg_to_full_width64(reg);

        // dr_get_thread_id

        if(tainted_regs.find(reg) != tainted_regs.end()) {
            return true;
        }
    } else if(opnd_is_memory_reference(opnd)) {
        dr_mcontext_t mc = {sizeof(mc),DR_MC_ALL};
        dr_get_mcontext(drcontext, &mc);
        app_pc addr = opnd_compute_address(opnd, &mc);

        opnd_size_t dr_size = opnd_get_size(opnd);
        uint size = opnd_size_in_bytes(dr_size);
        for(uint i=0; i<size; i++) {
            if(tainted_mems.find(addr+i) != tainted_mems.end()) {
                return true;
            }
        }

        if(opnd_is_base_disp(opnd)) {
            reg_id_t reg_base = opnd_get_base(opnd);
            reg_id_t reg_disp = opnd_get_disp(opnd);
            reg_id_t reg_indx = opnd_get_index(opnd);

            if(reg_base != NULL && tainted_regs.find(reg_base) != tainted_regs.end()) {
                return true;
            }

            if(reg_disp != NULL && tainted_regs.find(reg_disp) != tainted_regs.end()) {
                return true;
            }
            
            if (reg_indx != NULL && tainted_regs.find(reg_indx) != tainted_regs.end()) {
                return true;
            }
        }
    } 
    // else if(opnd_is_pc(opnd)) {
    //     opnd_get_pc(opnd);
    // } else if(opnd_is_abs_addr(opnd)) {
    //     opnd_get_addr(opnd);
    // }
    return false;
}

static void
taint_mem(app_pc addr, uint size) {
    for(uint i=0; i<size; i++) {
        tainted_mems.insert(addr+i);
    }
    dr_fprintf(STDERR, "tainted_mems size: %d\n", tainted_mems.size());
}

static bool
untaint_mem(app_pc addr, uint size) {
    /* TODO: 
        this seems to be off by 1 on (goes into a tainted buffer):
        rep movs %ds:(%rsi)[1byte] %rsi %rdi %rcx -> %es:(%rdi)[1byte] %rsi %rdi %rcx
        see WinHttpReadData test
    */
    bool untainted = false;
    for(uint i=0; i<size; i++) {
        size_t n = tainted_mems.erase(addr+i);
        if(n) {
            untainted = true;
        }
        if(untainted) {
        }
    }
    return untainted;
}

static void
taint(void *drcontext, opnd_t opnd) 
{
    if(opnd_is_reg(opnd)) {
        reg_id_t reg = opnd_get_reg(opnd);
        reg = reg_to_full_width64(reg);

        tainted_regs.insert(reg);
        
        // char buf[100];
        // opnd_disassemble_to_buffer(drcontext, opnd, buf, 100);
    } else if(opnd_is_memory_reference(opnd)) {
        dr_mcontext_t mc = {sizeof(mc),DR_MC_ALL};
        dr_get_mcontext(drcontext, &mc);
        app_pc addr = opnd_compute_address(opnd, &mc);

        // opnd get size
        opnd_size_t dr_size = opnd_get_size(opnd);
        // opnd size in bytes
        uint size = opnd_size_in_bytes(dr_size);
        // loop insert
        taint_mem(addr, size);
    } 
    // else if(opnd_is_pc(opnd)) {
    //     opnd_get_pc(opnd);
    // } else if(opnd_is_abs_addr(opnd)) {
    //     opnd_get_addr(opnd);
    // }
    
    return;
}

static bool
untaint(void *drcontext, opnd_t opnd) 
{
    bool untainted = false;
    if(opnd_is_reg(opnd)) {
        reg_id_t reg = opnd_get_reg(opnd);
        reg = reg_to_full_width64(reg);

        size_t n = tainted_regs.erase(reg);
        if(n) {
            // char buf[100];
            // opnd_disassemble_to_buffer(drcontext, opnd, buf, 100);
            untainted = true;
        }
    } else if(opnd_is_memory_reference(opnd)) {
        dr_mcontext_t mc = {sizeof(mc),DR_MC_ALL};
        dr_get_mcontext(drcontext, &mc);
        app_pc addr = opnd_compute_address(opnd, &mc);

        // opnd get size
        opnd_size_t dr_size = opnd_get_size(opnd);
        // opnd size in bytes
        uint size = opnd_size_in_bytes(dr_size);
        // loop insert
        untainted = untaint_mem(addr, size);
    } 
    // else if(opnd_is_pc(opnd)) {
    //     opnd_get_pc(opnd);
    // } else if(opnd_is_abs_addr(opnd)) {
    //     opnd_get_addr(opnd);
    // }
    
    return untainted;
}


static bool
handle_xor(void *drcontext, instr_t *instr) {
    bool result = false;
    int src_count = instr_num_srcs(instr);

    if(src_count == 2) {
        opnd_t opnd_0 = instr_get_src(instr, 0);
        opnd_t opnd_1 = instr_get_src(instr, 1);

        if(opnd_is_reg(opnd_0) && opnd_is_reg(opnd_1)) {
            reg_id_t reg_0 = opnd_get_reg(opnd_0);
            reg_id_t reg_1 = opnd_get_reg(opnd_1);

            if(reg_0 == reg_1) {
                size_t n = tainted_regs.erase(reg_0);
                // if(n) {
                //     char buf[100];
                //     opnd_disassemble_to_buffer(drcontext, opnd_0, buf, 100);
                // }
                result = true;
            }
        }
    }

    return result;
}

static void
handle_push_pop(void *drcontext, instr_t *instr) {
    int src_count = instr_num_srcs(instr);
    bool tainted = false;

    // check sources for taint
    for(int i=0; i<src_count && !tainted; i++) {
        opnd_t opnd = instr_get_src(instr, i);
        tainted |= is_tainted(drcontext, opnd);
    }

    // if tainted
    // taint destinations that aren't rsp
    int dst_count = instr_num_dsts(instr);
    for(int i=0; i<dst_count && tainted; i++) {
        opnd_t opnd = instr_get_dst(instr, i);

        if(opnd_is_reg(opnd)) {
            reg_id_t reg = opnd_get_reg(opnd);
            reg = reg_to_full_width64(reg);
            if(reg == DR_REG_RSP) {
                continue;
            }
        }

        taint(drcontext, opnd);
    }

    // if not tainted
    // untaint destinations that aren't rsp
    bool untainted = false;
    for(int i=0; i<dst_count && !tainted; i++) {
        opnd_t opnd = instr_get_dst(instr, i);

        if(opnd_is_reg(opnd)) {
            reg_id_t reg = opnd_get_reg(opnd);
            reg = reg_to_full_width64(reg);
            if(reg == DR_REG_RSP) {
                continue;
            }
        }

        untainted |= untaint(drcontext, opnd);
    }

    // 
    if(tainted | untainted) {
        int opcode = instr_get_opcode(instr);
        // char buf[100];
        // instr_disassemble_to_buffer(drcontext, instr, buf, 100);
    }
}

static bool
handle_xchg(void *drcontext, instr_t *instr) {
    bool result = false;
    int src_count = instr_num_srcs(instr);

    if(src_count == 2) {
        opnd_t opnd_0 = instr_get_src(instr, 0);
        opnd_t opnd_1 = instr_get_src(instr, 1);

        if(opnd_is_reg(opnd_0) && opnd_is_reg(opnd_1)) {
            reg_id_t reg_0 = opnd_get_reg(opnd_0);
            reg_id_t reg_1 = opnd_get_reg(opnd_1);


            bool reg_0_tainted = tainted_regs.find(reg_0) != tainted_regs.end();
            bool reg_1_tainted = tainted_regs.find(reg_1) != tainted_regs.end();

            if(reg_0_tainted && !reg_1_tainted) {
                tainted_regs.erase(reg_0);
                tainted_regs.insert(reg_1);
                result = true;
            } else if(reg_1_tainted && !reg_0_tainted) {
                tainted_regs.erase(reg_1);
                tainted_regs.insert(reg_0);
                result = true;
            }
        }
    }

    return result;
}

static bool
handle_branches(void *drcontext, instr_t *instr) {

    bool is_ret = instr_is_return(instr);
    bool is_direct = instr_is_ubr(instr) || instr_is_cbr(instr) || instr_is_call_direct(instr);
    bool is_indirect = instr_is_mbr(instr);
    bool is_call = instr_is_call(instr);

    if(!is_ret && !is_direct && !is_indirect && !is_call) {
        return false;
    }

    reg_id_t reg_pc = reg_to_full_width64(DR_REG_NULL);
    reg_id_t reg_stack = reg_to_full_width64(DR_REG_ESP);
    bool pc_tainted = tainted_regs.find(reg_pc) != tainted_regs.end();

    bool result = false;
    int src_count = instr_num_srcs(instr);
    int dst_count = instr_num_dsts(instr);

    // call
    if(is_call) {
        if(pc_tainted) {
            // taint mem at rsp
            for(int i=0; i<dst_count; i++) {
                opnd_t opnd = instr_get_dst(instr, i);
                if(opnd_is_memory_reference(opnd)) {
                    taint(drcontext, opnd);
                    break;
                }
            }
        }
    }

    // direct branch or call
    if(is_direct) {
        if(pc_tainted) {
            // untaint pc
            tainted_regs.erase(reg_pc);
        }
    }

    // indirect branch or call
    if(is_indirect) {
        for(int i=0; i<src_count; i++) {
            opnd_t opnd = instr_get_src(instr, i);

            if(opnd_is_reg(opnd)) {
                reg_id_t reg = opnd_get_reg(opnd);
                if(reg != reg_stack && tainted_regs.find(reg) != tainted_regs.end()) {
                    // taint pc
                    tainted_regs.insert(reg_pc);
                }
            }
        }
    }

    // ret
    if(is_ret) {
        bool tainted = false;
        for(int i=0; i<src_count; i++) {
            opnd_t opnd = instr_get_src(instr, i);
            if(is_tainted(drcontext, opnd)) {
                tainted = true;
                break;
            }
        }

        if(tainted){
            // taint pc
            tainted_regs.insert(reg_pc);
        } else {
            // untaint pc
            tainted_regs.erase(reg_pc);
        }
    }

    return true;
}

static bool
handle_specific(void *drcontext, instr_t *instr) {
    int opcode = instr_get_opcode(instr);
    bool result = false;

    // indirect call
    if(handle_branches(drcontext, instr)) {
        return true;
    }

    switch(opcode) {
        // push
        case 18:
        // pop
        case 20:
            handle_push_pop(drcontext, instr);
            return true;
        // xor
        case 12:
            result = handle_xor(drcontext, instr);
            return result;
        // xchg
        case 62:
            result = handle_xchg(drcontext, instr);
            return result;
        default:
            return false;
    }

}

static void
propagate_taint(app_pc pc) 
{
    void *drcontext = dr_get_current_drcontext();
    instr_t instr;
    instr_init(drcontext, &instr);
    decode(drcontext, pc, &instr);

    // if(tainted_mems.size() > 0) {
    //     char buf[100];
    //     instr_disassemble_to_buffer(drcontext, &instr, buf, 100);
    //     dr_printf("%s\n", buf);
    // }

    if(handle_specific(drcontext, &instr)) {
        return;
    }

    int src_count = instr_num_srcs(&instr);
    bool tainted = false;

    for(int i=0; i<src_count && !tainted; i++) {
        opnd_t opnd = instr_get_src(&instr, i);
        tainted |= is_tainted(drcontext, opnd);
    }

    int dst_count = instr_num_dsts(&instr);

    for(int i=0; i<dst_count && tainted; i++) {
        opnd_t opnd = instr_get_dst(&instr, i);
        taint(drcontext, opnd);
    }

    bool untainted = false;
    for(int i=0; i<dst_count && !tainted; i++) {
        opnd_t opnd = instr_get_dst(&instr, i);
        untainted |= untaint(drcontext, opnd);
    }

    if(tainted | untainted) {
        int opcode = instr_get_opcode(&instr);
    }
}

static dr_emit_flags_t
event_app_instruction(
    void *drcontext, 
    void *tag, 
    instrlist_t *bb,
    instr_t *instr, 
    bool for_trace,
    bool translating, 
    void *user_data)
{
    if (!instr_is_app(instr))
        return DR_EMIT_DEFAULT;

    dr_insert_clean_call(drcontext, bb, instr, propagate_taint, false, 1, 
                OPND_CREATE_INTPTR(instr_get_app_pc(instr)));

    return DR_EMIT_DEFAULT;
}

static void
event_thread_init(void *drcontext)
{
    
}

static void
event_thread_exit(void *drcontext)
{
    
}

static void
event_exit_trace(void)
{
    if(!op_no_taint.get_value()) {
        if(!drmgr_unregister_bb_insertion_event(event_app_instruction)) {
            DR_ASSERT(false);
        }
    }

    if (!drmgr_unregister_thread_init_event(event_thread_init) ||
        !drmgr_unregister_thread_exit_event(event_thread_exit) ||
        !drmgr_unregister_bb_insertion_event(event_app_instruction) ||
        drreg_exit() != DRREG_SUCCESS)
    {
        DR_ASSERT(false);
    }

    drmgr_exit();
}

static void
dump_regs(void *drcontext, app_pc exception_address) {
    reg_id_t regs[16] = { 
        DR_REG_RAX, 
        DR_REG_RBX, 
        DR_REG_RCX, 
        DR_REG_RDX, 
        DR_REG_RSP, 
        DR_REG_RBP, 
        DR_REG_RSI, 
        DR_REG_RDI, 
        DR_REG_R8, 
        DR_REG_R9, 
        DR_REG_R10, 
        DR_REG_R11, 
        DR_REG_R12, 
        DR_REG_R13, 
        DR_REG_R14, 
        DR_REG_R15, 
    };

    std::set<reg_id_t>::iterator reg_it;
    for(reg_it = tainted_regs.begin(); reg_it != tainted_regs.end(); reg_it++) {
    }

    std::set<app_pc>::iterator mem_it;
    for(mem_it = tainted_mems.begin(); mem_it != tainted_mems.end(); mem_it++) {
    }

    for(int i=0; i<16; i++) {
        bool tainted = tainted_regs.find(regs[i]) != tainted_regs.end();
        dr_mcontext_t mc = {sizeof(mc),DR_MC_ALL};
        dr_get_mcontext(drcontext, &mc);
        if(tainted) {
        } else {
        }
    }

    bool tainted = tainted_regs.find(DR_REG_NULL) != tainted_regs.end();
    if(tainted) {
    } else {
    }
}

std::string
exception_to_string(DWORD exception_code) {
    std::string exception_str = "UNKNOWN";
    switch (exception_code) {
        case EXCEPTION_ACCESS_VIOLATION:
            exception_str = "EXCEPTION_ACCESS_VIOLATION";
            break;
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            exception_str = "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
            break;
        case EXCEPTION_BREAKPOINT:
            exception_str = "EXCEPTION_BREAKPOINT";
            break;
        case EXCEPTION_DATATYPE_MISALIGNMENT:
            exception_str = "EXCEPTION_DATATYPE_MISALIGNMENT";
            break;
        case EXCEPTION_FLT_DENORMAL_OPERAND:
            exception_str = "EXCEPTION_FLT_DENORMAL_OPERAND";
            break;
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
            exception_str = "EXCEPTION_FLT_DIVIDE_BY_ZERO";
            break;
        case EXCEPTION_FLT_INEXACT_RESULT:
            exception_str = "EXCEPTION_FLT_INEXACT_RESULT";
            break;
        case EXCEPTION_FLT_INVALID_OPERATION:
            exception_str = "EXCEPTION_FLT_INVALID_OPERATION";
            break;
        case EXCEPTION_FLT_OVERFLOW:
            exception_str = "EXCEPTION_FLT_OVERFLOW";
            break;
        case EXCEPTION_FLT_STACK_CHECK:
            exception_str = "EXCEPTION_FLT_STACK_CHECK";
            break;
        case EXCEPTION_FLT_UNDERFLOW:
            exception_str = "EXCEPTION_FLT_UNDERFLOW";
            break;
        case EXCEPTION_ILLEGAL_INSTRUCTION:
            exception_str = "EXCEPTION_ILLEGAL_INSTRUCTION";
            break;
        case EXCEPTION_IN_PAGE_ERROR:
            exception_str = "EXCEPTION_IN_PAGE_ERROR";
            break;
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
            exception_str = "EXCEPTION_INT_DIVIDE_BY_ZERO";
            break;
        case EXCEPTION_INT_OVERFLOW:
            exception_str = "EXCEPTION_INT_OVERFLOW";
            break;
        case EXCEPTION_INVALID_DISPOSITION:
            exception_str = "EXCEPTION_INVALID_DISPOSITION";
            break;
        case EXCEPTION_NONCONTINUABLE_EXCEPTION:
            exception_str = "EXCEPTION_NONCONTINUABLE_EXCEPTION";
            break;
        case EXCEPTION_PRIV_INSTRUCTION:
            exception_str = "EXCEPTION_PRIV_INSTRUCTION";
            break;
        case EXCEPTION_SINGLE_STEP:
            exception_str = "EXCEPTION_SINGLE_STEP";
            break;
        case EXCEPTION_STACK_OVERFLOW:
            exception_str = "EXCEPTION_STACK_OVERFLOW";
            break;
        default:
            break;
    }

    return exception_str;
}

std::string
dump_json(void *drcontext, uint8_t score, std::string reason, dr_exception_t *excpt, std::string disassembly) {
    DWORD exception_code = excpt->record->ExceptionCode;
    app_pc exception_address = (app_pc)excpt->record->ExceptionAddress;

    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);

    writer.StartObject();

    writer.Key("score");
    writer.Uint(score);

    writer.Key("reason");
    writer.String(reason.c_str());

    writer.Key("exception");
    writer.String(exception_to_string(exception_code).c_str());

    writer.Key("location");
    writer.Uint64((uint64)exception_address);

    writer.Key("instruction");
    writer.String(disassembly.c_str());

    writer.Key("tainted_regs");
    writer.StartArray();
    reg_id_t regs[16] = { 
        DR_REG_RAX, 
        DR_REG_RBX, 
        DR_REG_RCX, 
        DR_REG_RDX, 
        DR_REG_RSP, 
        DR_REG_RBP, 
        DR_REG_RSI, 
        DR_REG_RDI, 
        DR_REG_R8, 
        DR_REG_R9, 
        DR_REG_R10, 
        DR_REG_R11, 
        DR_REG_R12, 
        DR_REG_R13, 
        DR_REG_R14, 
        DR_REG_R15, 
    };

    for(int i=0; i<16; i++) {
        bool tainted = tainted_regs.find(regs[i]) != tainted_regs.end();

        writer.StartObject();
        writer.Key("reg");
        writer.String(get_register_name(regs[i]));
        writer.Key("value");
        writer.Uint64(reg_get_value(regs[i], excpt->mcontext));
        writer.Key("tainted");
        writer.Bool(tainted);
        writer.EndObject();
    }

    bool tainted = tainted_regs.find(DR_REG_NULL) != tainted_regs.end();
    writer.StartObject();
    writer.Key("reg");
    writer.String("rip");
    writer.Key("value");
    writer.Uint64((uint64)exception_address);
    writer.Key("tainted");
    writer.Bool(tainted);
    writer.EndObject();

    writer.EndArray();

    writer.Key("tainted_addrs");
    writer.StartArray();
    if (tainted_mems.size() > 0) {
        std::set<app_pc>::iterator mit = tainted_mems.begin();
        UINT64 start = (UINT64)*mit;
        UINT64 size = 1;

        mit++;
        for (; mit != tainted_mems.end(); mit++) {
            UINT64 curr = (UINT64)*mit;
            if (curr > (start + size)) {
                writer.StartObject();
                writer.Key("start");
                writer.Uint64(start);
                writer.Key("size");
                writer.Uint64(size);
                writer.EndObject();

                start = curr;
                size = 0;
            }
            size++;
        }

        writer.StartObject();
        writer.Key("start");
        writer.Uint64(start);
        writer.Key("size");
        writer.Uint64(size);
        writer.EndObject();
    }
    writer.EndArray();

    writer.EndObject();

    return s.GetString();
}

static void
dump_crash(void *drcontext, dr_exception_t *excpt, std::string reason, uint8_t score, std::string disassembly) {
    std::string crash_json = dump_json(drcontext, score, reason, excpt, disassembly);

    WCHAR targetFile[MAX_PATH + 1] = { 0 };
    ZeroMemory(targetFile, sizeof(WCHAR) * (MAX_PATH + 1));
    
    if(replay) {
        HANDLE h_pipe = CreateFile(
            L"\\\\.\\pipe\\fuzz_server",
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);

        if (h_pipe != INVALID_HANDLE_VALUE) {
            DWORD read_mode = PIPE_READMODE_MESSAGE;
            SetNamedPipeHandleState(
                h_pipe,
                &read_mode,
                NULL,
                NULL);

            DWORD bytes_read = 0;
            DWORD bytes_written = 0;

            BYTE event_id = 5;

            WriteFile(h_pipe, &event_id, sizeof(BYTE), &bytes_written, NULL);
            TransactNamedPipe(h_pipe, &run_id, sizeof(DWORD), targetFile, MAX_PATH + 1, &bytes_read, NULL);
            CloseHandle(h_pipe);

            HANDLE hCrashFile = CreateFile(targetFile, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hCrashFile == INVALID_HANDLE_VALUE) {
                dr_fprintf(STDERR, "Could not open crash file json (%x)", GetLastError());
                exit(1);
            }

            DWORD bytesWritten;
            if (!WriteFile(hCrashFile, crash_json.c_str(), crash_json.length(), &bytesWritten, NULL)) {
                dr_fprintf(STDERR, "Could not write crash file json (%x)", GetLastError());
                exit(1);
            }
        }
    }
        
    dr_printf("#### BEGIN CRASH DATA JSON\n");
    dr_printf("%s\n", crash_json.c_str());
    dr_printf("#### END CRASH DATA JSON\n");

    dr_exit_process(1);
}

static bool
onexception(void *drcontext, dr_exception_t *excpt) {
    DWORD exception_code = excpt->record->ExceptionCode;

    reg_id_t reg_pc = reg_to_full_width64(DR_REG_NULL);
    reg_id_t reg_stack = reg_to_full_width64(DR_REG_ESP);
    bool pc_tainted = tainted_regs.find(reg_pc) != tainted_regs.end();
    bool stack_tainted = tainted_regs.find(reg_stack) != tainted_regs.end();

    app_pc exception_address = (app_pc)(excpt->record->ExceptionAddress);
    std::string reason = "unknown";
    uint8_t score = 50;
    std::string disassembly = "";

    if(IsBadReadPtr(exception_address, 1)) {
        if(pc_tainted) {
            reason = "oob execution tainted pc";
            score = 100;
        } else {
            reason = "oob execution";
            score = 50;
        }
        dump_crash(drcontext, excpt, reason, score, disassembly);
    }

    instr_t instr;
    instr_init(drcontext, &instr);
    decode(drcontext, exception_address, &instr);
    char buf[100];
    instr_disassemble_to_buffer(drcontext, &instr, buf, 100);
    
    disassembly = buf;
    
    // check exception code
    if (exception_code == EXCEPTION_ILLEGAL_INSTRUCTION) {
        if(pc_tainted) {
            reason = "illegal instruction tainted pc";
            score = 100;
        } else {
            reason = "illegal instruction";
            score = 50;
        }
        dump_crash(drcontext, excpt, reason, score, disassembly);
    }

    if (exception_code == EXCEPTION_INT_DIVIDE_BY_ZERO) {
        reason = "floating point exception";
        score = 0;
        dump_crash(drcontext, excpt, reason, score, disassembly);
    }

    if (exception_code == EXCEPTION_BREAKPOINT) {
        reason = "breakpoint";
        score = 25;
        dump_crash(drcontext, excpt, reason, score, disassembly);
    }

    // get crashing instruction
    bool is_ret = instr_is_return(&instr);
    bool is_direct = instr_is_ubr(&instr) || instr_is_cbr(&instr) || instr_is_call_direct(&instr);
    bool is_indirect = instr_is_mbr(&instr);
    bool is_call = instr_is_call(&instr); // this might be covered in other flags

    // check branch
    if (is_direct || is_indirect || is_call) {
        if (pc_tainted) {
            reason = "branching tainted pc";
            score = 75;
        }
        else {
            reason = "branching";
            score = 25;
        }
        dump_crash(drcontext, excpt, reason, score, disassembly);
    }

    // check ret 
    if (is_ret) {
        if (pc_tainted || stack_tainted) {
            score = 100;
            reason = "return with taint";
        }
        else {
            reason = "return";
            score = 75;
        }

        dump_crash(drcontext, excpt, reason, score, disassembly);
    }

    bool mem_write = instr_writes_memory(&instr);
    bool mem_read = instr_reads_memory(&instr);
    bool tainted_src = false;
    bool tainted_dst = false;

    int src_count = instr_num_srcs(&instr);
    int dst_count = instr_num_dsts(&instr);


    for(int i=0; i<src_count; i++) {
        opnd_t opnd = instr_get_src(&instr, i);
        tainted_src |= is_tainted(drcontext, opnd);
    }

    for(int i=0; i<dst_count; i++) {
        opnd_t opnd = instr_get_dst(&instr, i);
        tainted_dst |= is_tainted(drcontext, opnd);
    }

    if(mem_write) {
        if(tainted_src || tainted_dst) {
            reason = "tainted write";
            score = 75;
        } else {
            reason = "write";
            score = 50;
        }
        dump_crash(drcontext, excpt, reason, score, disassembly);
    }

    if(mem_read) {
        if(tainted_src) {
            reason = "tainted read";
            score = 75;
        } else {
            reason = "read";
            score = 25;
        }
        dump_crash(drcontext, excpt, reason, score, disassembly);
    }

    dump_crash(drcontext, excpt, reason, score, disassembly);

    return true;
}

struct read_info {
    LPVOID lpBuffer;
    DWORD nNumberOfBytesToRead;
    Function function;
};

static void
wrap_pre_ReadEventLog(void *wrapcxt, OUT void **user_data) {
    dr_fprintf(STDERR, "<in wrap_pre_ReadEventLog>\n");
    HANDLE hEventLog = (HANDLE)drwrap_get_arg(wrapcxt, 0);
    DWORD  dwReadFlags = (DWORD)drwrap_get_arg(wrapcxt, 1);
    DWORD  dwRecordOffset = (DWORD)drwrap_get_arg(wrapcxt, 2);
    LPVOID lpBuffer = (LPVOID)drwrap_get_arg(wrapcxt, 3);
    DWORD  nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 4);
    DWORD  *pnBytesRead = (DWORD *)drwrap_get_arg(wrapcxt, 5);
    DWORD  *pnMinNumberOfBytesNeeded = (DWORD *)drwrap_get_arg(wrapcxt, 6);
    
    *user_data = malloc(sizeof(read_info));
    ((read_info *)*user_data)->lpBuffer = lpBuffer;
    ((read_info *)*user_data)->nNumberOfBytesToRead = nNumberOfBytesToRead;
    ((read_info *)*user_data)->function = Function::ReadEventLog;
}

static void
wrap_pre_RegQueryValueEx(void *wrapcxt, OUT void **user_data) {
    dr_fprintf(STDERR, "<in wrap_pre_RegQueryValueEx>\n");
    HKEY    hKey = (HKEY)drwrap_get_arg(wrapcxt, 0);
    LPCTSTR lpValueName = (LPCTSTR)drwrap_get_arg(wrapcxt, 1);
    LPDWORD lpReserved = (LPDWORD)drwrap_get_arg(wrapcxt, 2);
    LPDWORD lpType = (LPDWORD)drwrap_get_arg(wrapcxt, 3);
    LPBYTE  lpData = (LPBYTE)drwrap_get_arg(wrapcxt, 4);
    LPDWORD lpcbData = (LPDWORD)drwrap_get_arg(wrapcxt, 5);

    if(lpData != NULL && lpcbData != NULL) {
        *user_data = malloc(sizeof(read_info));
        ((read_info *)*user_data)->lpBuffer = lpData;
        ((read_info *)*user_data)->nNumberOfBytesToRead = *lpcbData;
        ((read_info *)*user_data)->function = Function::RegQueryValueEx;
    } else {
        *user_data = NULL;
    }
}

static void
wrap_pre_WinHttpWebSocketReceive(void *wrapcxt, OUT void **user_data) {
    dr_fprintf(STDERR, "<in wrap_pre_WinHttpWebSocketReceive>\n");
    HINTERNET hRequest = (HINTERNET)drwrap_get_arg(wrapcxt, 0);
    PVOID pvBuffer = drwrap_get_arg(wrapcxt, 1);
    DWORD dwBufferLength = (DWORD)drwrap_get_arg(wrapcxt, 2);
    PDWORD pdwBytesRead = (PDWORD)drwrap_get_arg(wrapcxt, 3);
    WINHTTP_WEB_SOCKET_BUFFER_TYPE peBufferType = (WINHTTP_WEB_SOCKET_BUFFER_TYPE)(int)drwrap_get_arg(wrapcxt, 3);
    
    *user_data = malloc(sizeof(read_info));
    ((read_info *)*user_data)->lpBuffer = pvBuffer;
    ((read_info *)*user_data)->nNumberOfBytesToRead = dwBufferLength;
    ((read_info *)*user_data)->function = Function::WinHttpWebSocketReceive;
}

static void
wrap_pre_InternetReadFile(void *wrapcxt, OUT void **user_data) {
    dr_fprintf(STDERR, "<in wrap_pre_InternetReadFile>\n");
    HINTERNET hFile = (HINTERNET)drwrap_get_arg(wrapcxt, 0);
    LPVOID lpBuffer = drwrap_get_arg(wrapcxt, 1);
    DWORD nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 2);
    LPDWORD lpNumberOfBytesRead = (LPDWORD)drwrap_get_arg(wrapcxt, 3);
    
    *user_data = malloc(sizeof(read_info));
    ((read_info *)*user_data)->lpBuffer = lpBuffer;
    ((read_info *)*user_data)->nNumberOfBytesToRead = nNumberOfBytesToRead;
    ((read_info *)*user_data)->function = Function::InternetReadFile;
}

static void
wrap_pre_WinHttpReadData(void *wrapcxt, OUT void **user_data) {
    dr_fprintf(STDERR, "<in wrap_pre_WinHttpReadData>\n");
    HINTERNET hRequest = (HINTERNET)drwrap_get_arg(wrapcxt, 0);
    LPVOID lpBuffer = drwrap_get_arg(wrapcxt, 1);
    DWORD nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 2);
    LPDWORD lpNumberOfBytesRead = (LPDWORD)drwrap_get_arg(wrapcxt, 3);
    
    *user_data = malloc(sizeof(read_info));
    ((read_info *)*user_data)->lpBuffer = lpBuffer;
    ((read_info *)*user_data)->nNumberOfBytesToRead = nNumberOfBytesToRead;
    ((read_info *)*user_data)->function = Function::WinHttpReadData;
}

static void
wrap_pre_recv(void *wrapcxt, OUT void **user_data) {
    dr_fprintf(STDERR, "<in wrap_pre_recv>\n");
    SOCKET s = (SOCKET)drwrap_get_arg(wrapcxt, 0);
    char *buf = (char *)drwrap_get_arg(wrapcxt, 1);
    int len = (int)drwrap_get_arg(wrapcxt, 2);
    int flags = (int)drwrap_get_arg(wrapcxt, 3);
    
    *user_data = malloc(sizeof(read_info));
    ((read_info *)*user_data)->lpBuffer = buf;
    ((read_info *)*user_data)->nNumberOfBytesToRead = len;
    ((read_info *)*user_data)->function = Function::recv;
}

static void
wrap_pre_ReadFile(void *wrapcxt, OUT void **user_data) {
    dr_fprintf(STDERR, "<in wrap_pre_ReadFile>\n");
    HANDLE hFile = drwrap_get_arg(wrapcxt, 0);
    LPVOID lpBuffer = drwrap_get_arg(wrapcxt, 1);
    DWORD nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 2);
    LPDWORD lpNumberOfBytesRead = (LPDWORD)drwrap_get_arg(wrapcxt, 3);
    
    *user_data = malloc(sizeof(read_info));
    ((read_info *)*user_data)->lpBuffer = lpBuffer;
    ((read_info *)*user_data)->nNumberOfBytesToRead = nNumberOfBytesToRead;
    ((read_info *)*user_data)->function = Function::ReadFile;
}

static void
wrap_post_GenericTaint(void *wrapcxt, void *user_data) {
    dr_fprintf(STDERR, "<in wrap_post_GenericTaint>\n");
    if(user_data == NULL) {
        return;
    }

    LPVOID lpBuffer = ((read_info *)user_data)->lpBuffer;
    DWORD nNumberOfBytesToRead = ((read_info *)user_data)->nNumberOfBytesToRead;
    Function function = ((read_info *)user_data)->function;
    free(user_data);

    BOOL targeted = true;
    std::string target = op_target.get_value();
    CHAR *functionName = get_function_name(function);

    if(target != "") {
        targeted = false;
        if(target.find(functionName) != std::string::npos) {
            char *end;
            UINT64 num = strtoull(target.c_str(), &end, 10);
            if(call_counts[function] == num) {
                targeted = true;
            }
        }
    }

    call_counts[function]++;

    if(targeted) {
        taint_mem((app_pc)lpBuffer, nNumberOfBytesToRead);
    }

    if(replay && targeted) {
        dr_mutex_lock(mutatex);
        HANDLE h_pipe = CreateFile(
            L"\\\\.\\pipe\\fuzz_server",
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);

        if (h_pipe != INVALID_HANDLE_VALUE) {
            DWORD read_mode = PIPE_READMODE_MESSAGE;
            SetNamedPipeHandleState(
                h_pipe,
                &read_mode,
                NULL,
                NULL);

            DWORD bytes_read = 0;
            DWORD bytes_written = 0;

            BYTE event_id = 2;

            WriteFile(h_pipe, &event_id, sizeof(BYTE), &bytes_written, NULL);
            WriteFile(h_pipe, &run_id, sizeof(DWORD), &bytes_written, NULL);
            WriteFile(h_pipe, &mutate_count, sizeof(DWORD), &bytes_written, NULL);
            TransactNamedPipe(h_pipe, &nNumberOfBytesToRead, sizeof(DWORD), lpBuffer, nNumberOfBytesToRead, &bytes_read, NULL);
            mutate_count++;
            CloseHandle(h_pipe);
            dr_mutex_unlock(mutatex);
        }
    }
}

static void
module_load_event(void *drcontext, const module_data_t *mod, bool loaded) {
    // void(__cdecl *)(void *, OUT void **)
#define PREPROTO void(__cdecl *)(void *, void **)
#define POSTPROTO void(__cdecl *)(void *, void *)

    std::map<char *, PREPROTO> toHookPre;
    toHookPre["ReadEventLog"] = wrap_pre_ReadEventLog;
    toHookPre["RegQueryValueExW"] = wrap_pre_RegQueryValueEx;
    toHookPre["RegQueryValueExA"] = wrap_pre_RegQueryValueEx;
    toHookPre["WinHttpWebSocketReceive"] = wrap_pre_WinHttpWebSocketReceive;
    toHookPre["InternetReadFile"] = wrap_pre_InternetReadFile;
    toHookPre["WinHttpReadData"] = wrap_pre_WinHttpReadData;
    toHookPre["recv"] = wrap_pre_recv;
    toHookPre["ReadFile"] = wrap_pre_ReadFile;
    
    std::map<char *, POSTPROTO> toHookPost;
    toHookPost["ReadFile"] = wrap_post_GenericTaint;
    toHookPost["InternetReadFile"] = wrap_post_GenericTaint;
    toHookPost["ReadEventLog"] = wrap_post_GenericTaint;
    toHookPost["RegQueryValueExW"] = wrap_post_GenericTaint;
    toHookPost["RegQueryValueExA"] = wrap_post_GenericTaint;
    toHookPost["WinHttpWebSocketReceive"] = wrap_post_GenericTaint;
    toHookPost["WinHttpReadData"] = wrap_post_GenericTaint;
    toHookPost["recv"] = wrap_post_GenericTaint;

    std::map<char *, PREPROTO>::iterator it;
    for(it = toHookPre.begin(); it != toHookPre.end(); it++) {
        char *functionName = it->first;
        std::string include = op_include.get_value();

        if(include != "" && include.find(functionName) == std::string::npos) {
            continue;
        }

        void(__cdecl *hookFunctionPre)(void *, void **);
        hookFunctionPre = it->second;
        void(__cdecl *hookFunctionPost)(void *, void *);
        hookFunctionPost = NULL;

        if(toHookPost.find(functionName) != toHookPost.end()) {
            hookFunctionPost = toHookPost[functionName];
        }

        app_pc towrap = (app_pc) dr_get_proc_address(mod->handle, functionName);
        const char *mod_name = dr_module_preferred_name(mod);
        if(strcmp(functionName, "ReadFile") == 0) {
            if(strcmp(mod_name, "KERNELBASE.dll") != 0) {
                continue;
            }
        }

        if(strcmp(functionName, "RegQueryValueExA") == 0 || strcmp(functionName, "RegQueryValueExW") == 0) {
            if(strcmp(mod_name, "KERNELBASE.dll") != 0) {
                continue;
            }
        }

        if (towrap != NULL) {
            dr_flush_region(towrap, 0x1000);
            bool ok = drwrap_wrap(towrap, hookFunctionPre, hookFunctionPost);
            // bool ok = false;
            if (ok) {
                dr_fprintf(STDERR, "<wrapped %s @ 0x%p\n", functionName, towrap);
            } else {
                dr_fprintf(STDERR, "<FAILED to wrap %s @ 0x%p: already wrapped?\n", functionName, towrap);
            }
        }
    }
}

#define NO_REPLAY 0xFFFFFFF
static droption_t<unsigned int> op_replay
(DROPTION_SCOPE_CLIENT, "r", NO_REPLAY, "replay",
 "The run id for a crash to replay.");

void tracer(client_id_t id, int argc, const char *argv[]) {
    drreg_options_t ops = {sizeof(ops), 3, false};
    dr_set_client_name("DynamoRIO Sample Client 'instrace'",
                       "http://dynamorio.org/issues");

    if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS || !drwrap_init())
        DR_ASSERT(false);

    replay = false;
    mutate_count = 0;

    run_id = op_replay.get_value();
    if(run_id != NO_REPLAY) {
        replay = true;
    }
    
    dr_printf("replay: %d\n", replay);
    dr_printf("run_id: %llu\n", run_id);

    mutatex = dr_mutex_create();
    dr_register_exit_event(event_exit_trace);

    if(!op_no_taint.get_value()) {
        if(!drmgr_register_bb_instrumentation_event(
                                                NULL,
                                                 event_app_instruction,
                                                 NULL)) 
        {
            DR_ASSERT(false);
        }
    }

    if (!drmgr_register_module_load_event(module_load_event) ||
        !drmgr_register_thread_init_event(event_thread_init) ||
        !drmgr_register_thread_exit_event(event_thread_exit) ||
        !drmgr_register_exception_event(onexception)) 
    {
        DR_ASSERT(false);
    }

    dr_log(NULL, LOG_ALL, 1, "Client 'instrace' initializing\n");
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    std::string parse_err;
    int last_idx = 0;
    if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, &parse_err, &last_idx)) {
        dr_fprintf(STDERR, "Usage error: %s", parse_err.c_str());
        dr_abort();
    }

    tracer(id, argc, argv);
}
