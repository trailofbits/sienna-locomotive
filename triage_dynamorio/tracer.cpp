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

extern "C" {
#include "utils.h"
}

#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

#include "Dbghelp.h"
#include "Windows.h"

std::set<reg_id_t> tainted_regs;
std::set<app_pc> tainted_mems;

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
            if(tainted_mems.find(addr) != tainted_mems.end()) {
                return true;
            }
        }

        if(opnd_is_base_disp(opnd)) {
            reg_id_t reg_base = opnd_get_base(opnd);
            reg_id_t reg_disp = opnd_get_disp(opnd);
            reg_id_t reg_indx = opnd_get_index(opnd);

            if(reg_base != NULL && tainted_regs.find(reg_base) != tainted_regs.end()) {
                dr_printf("tainted base: %s\n", get_register_name(reg_base));
                return true;
            }

            if(reg_disp != NULL && tainted_regs.find(reg_disp) != tainted_regs.end()) {
                dr_printf("tainted disp: %s\n", get_register_name(reg_disp));
                return true;
            }
            
            if (reg_indx != NULL && tainted_regs.find(reg_indx) != tainted_regs.end()) {
                dr_printf("tainted index: %s\n", get_register_name(reg_indx));
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
        dr_printf("tainting: %llx\n", addr+i);
        tainted_mems.insert(addr+i);
    }
}

static bool
untaint_mem(app_pc addr, uint size) {
    bool untainted = false;
    for(uint i=0; i<size; i++) {
        size_t n = tainted_mems.erase(addr+i);
        if(n) {
            dr_printf("untainting: %llx\n", addr+i);
            untainted = true;
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
        
        char buf[100];
        opnd_disassemble_to_buffer(drcontext, opnd, buf, 100);
        dr_printf("tainting: %s\n", buf);
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
            char buf[100];
            opnd_disassemble_to_buffer(drcontext, opnd, buf, 100);
            dr_printf("untainting: %s\n", buf);
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
                if(n) {
                    char buf[100];
                    opnd_disassemble_to_buffer(drcontext, opnd_0, buf, 100);
                    dr_printf("untainting: %s\n", buf);
                }
                result = true;
            }
        }
    }

    return result;
}

static void
handle_pop(void *drcontext, instr_t *instr) {
    int src_count = instr_num_srcs(instr);
    bool tainted = false;

    for(int i=0; i<src_count && !tainted; i++) {
        opnd_t opnd = instr_get_src(instr, i);
        tainted |= is_tainted(drcontext, opnd);
    }

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

    if(tainted | untainted) {
        int opcode = instr_get_opcode(instr);
        char buf[100];
        instr_disassemble_to_buffer(drcontext, instr, buf, 100);
        dr_printf("POP: (%d) %s\n", opcode, buf);
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
                dr_printf("untainting: %s\n", get_register_name(reg_0));
                dr_printf("tainting: %s\n", get_register_name(reg_1));
                result = true;
            } else if(reg_1_tainted && !reg_0_tainted) {
                tainted_regs.erase(reg_1);
                tainted_regs.insert(reg_0);
                dr_printf("untainting: %s\n", get_register_name(reg_1));
                dr_printf("tainting: %s\n", get_register_name(reg_0));
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

    // int opcode = instr_get_opcode(instr);
    // char buf[100];
    // instr_disassemble_to_buffer(drcontext, instr, buf, 100);
    // dr_printf("(%d) %s\n", opcode, buf);

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

/* 
    // call
    if(is_call) {
        if pc is tainted
            taint mem at rsp
    }

    // direct branch or call
    if(is_direct) {
        if pc is tainted
            untaint pc
    }

    // indirect branch or call
    if(is_indirect) {
        if reg_s != stack && reg_s is tainted
            taint pc
    }

    // ret
    if(is_ret) {
        if rsp is tainted or mem at rsp is tainted
            taint pc
        else
            untaint pc
    }
*/

static bool
handle_specific(void *drcontext, instr_t *instr) {
    int opcode = instr_get_opcode(instr);
    bool result = false;

    // indirect call
    if(handle_branches(drcontext, instr)) {
        return true;
    }

    switch(opcode) {
        // pop
        case 20:
            handle_pop(drcontext, instr);
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
        char buf[100];
        instr_disassemble_to_buffer(drcontext, &instr, buf, 100);
        dr_printf("INS: (%d) %s\n", opcode, buf);
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
        dr_printf("TAINTED REGS: %s\n", get_register_name(*reg_it));
    }

    std::set<app_pc>::iterator mem_it;
    for(mem_it = tainted_mems.begin(); mem_it != tainted_mems.end(); mem_it++) {
        dr_printf("TAINTED MEMS: %llx\n", *mem_it);
    }

    for(int i=0; i<16; i++) {
        bool tainted = tainted_regs.find(regs[i]) != tainted_regs.end();
        dr_mcontext_t mc = {sizeof(mc),DR_MC_ALL};
        dr_get_mcontext(drcontext, &mc);
        if(tainted) {
            dr_printf("%s*: %llx\n", get_register_name(regs[i]), reg_get_value(regs[i], &mc));
        } else {
            dr_printf("%s: %llx\n", get_register_name(regs[i]), reg_get_value(regs[i], &mc));
        }
    }

    bool tainted = tainted_regs.find(DR_REG_NULL) != tainted_regs.end();
    if(tainted) {
        dr_printf("rip*: %llx\n", exception_address);
    } else {
        dr_printf("rip: %llx\n", exception_address);
    }
}

std::string
exception_to_string(DWORD exceptionCode) {
    std::string exceptionStr = "UNKNOWN";
    switch (exceptionCode) {
        case EXCEPTION_ACCESS_VIOLATION:
            exceptionStr = "EXCEPTION_ACCESS_VIOLATION";
            break;
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            exceptionStr = "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
            break;
        case EXCEPTION_BREAKPOINT:
            exceptionStr = "EXCEPTION_BREAKPOINT";
            break;
        case EXCEPTION_DATATYPE_MISALIGNMENT:
            exceptionStr = "EXCEPTION_DATATYPE_MISALIGNMENT";
            break;
        case EXCEPTION_FLT_DENORMAL_OPERAND:
            exceptionStr = "EXCEPTION_FLT_DENORMAL_OPERAND";
            break;
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
            exceptionStr = "EXCEPTION_FLT_DIVIDE_BY_ZERO";
            break;
        case EXCEPTION_FLT_INEXACT_RESULT:
            exceptionStr = "EXCEPTION_FLT_INEXACT_RESULT";
            break;
        case EXCEPTION_FLT_INVALID_OPERATION:
            exceptionStr = "EXCEPTION_FLT_INVALID_OPERATION";
            break;
        case EXCEPTION_FLT_OVERFLOW:
            exceptionStr = "EXCEPTION_FLT_OVERFLOW";
            break;
        case EXCEPTION_FLT_STACK_CHECK:
            exceptionStr = "EXCEPTION_FLT_STACK_CHECK";
            break;
        case EXCEPTION_FLT_UNDERFLOW:
            exceptionStr = "EXCEPTION_FLT_UNDERFLOW";
            break;
        case EXCEPTION_ILLEGAL_INSTRUCTION:
            exceptionStr = "EXCEPTION_ILLEGAL_INSTRUCTION";
            break;
        case EXCEPTION_IN_PAGE_ERROR:
            exceptionStr = "EXCEPTION_IN_PAGE_ERROR";
            break;
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
            exceptionStr = "EXCEPTION_INT_DIVIDE_BY_ZERO";
            break;
        case EXCEPTION_INT_OVERFLOW:
            exceptionStr = "EXCEPTION_INT_OVERFLOW";
            break;
        case EXCEPTION_INVALID_DISPOSITION:
            exceptionStr = "EXCEPTION_INVALID_DISPOSITION";
            break;
        case EXCEPTION_NONCONTINUABLE_EXCEPTION:
            exceptionStr = "EXCEPTION_NONCONTINUABLE_EXCEPTION";
            break;
        case EXCEPTION_PRIV_INSTRUCTION:
            exceptionStr = "EXCEPTION_PRIV_INSTRUCTION";
            break;
        case EXCEPTION_SINGLE_STEP:
            exceptionStr = "EXCEPTION_SINGLE_STEP";
            break;
        case EXCEPTION_STACK_OVERFLOW:
            exceptionStr = "EXCEPTION_STACK_OVERFLOW";
            break;
        default:
            break;
    }

    return exceptionStr;
}

std::string
dump_json(void *drcontext, uint8_t score, std::string reason, DWORD exception_code, app_pc exception_address) {
    rapidjson::StringBuffer s;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(s);

    writer.StartObject();

    writer.Key("score");
    writer.Uint(score);

    writer.Key("reason");
    writer.String(reason.c_str());

    writer.Key("exception");
    writer.String(exception_to_string(exception_code).c_str());

    writer.Key("location");
    writer.Uint64((uint64)exception_address);

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
        dr_mcontext_t mc = {sizeof(mc),DR_MC_ALL};
        dr_get_mcontext(drcontext, &mc);

        writer.StartObject();
        writer.Key("reg");
        writer.String(get_register_name(regs[i]));
        writer.Key("value");
        writer.Uint64(reg_get_value(regs[i], &mc));
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
dump_crash(void *drcontext, app_pc exception_address, DWORD exception_code, std::string reason, uint8_t score) {
    std::string crash_json = dump_json(drcontext, score, reason, exception_code, exception_address);
    
    dr_printf("%s\n", crash_json.c_str());
    dr_exit_process(1);
}

static bool
onexception(void *drcontext, dr_exception_t *excpt) {
    DWORD num_written;
    DWORD exception_code = excpt->record->ExceptionCode;

    if((exception_code == EXCEPTION_ACCESS_VIOLATION) ||
       (exception_code == EXCEPTION_ILLEGAL_INSTRUCTION) ||
       (exception_code == EXCEPTION_PRIV_INSTRUCTION) ||
       (exception_code == EXCEPTION_STACK_OVERFLOW)) 
    {
        app_pc exception_address = (app_pc)(excpt->record->ExceptionAddress);
    dr_printf("In exception %llx\n", exception_address);
        std::string reason = "unknown";
        uint8_t score = 50;

        // check exception code
        if (exception_code == EXCEPTION_ILLEGAL_INSTRUCTION) {
            reason = "illegal instruction";
            score = 100;
            dump_crash(drcontext, exception_address, exception_code, reason, score);
        }

        if (exception_code == EXCEPTION_INT_DIVIDE_BY_ZERO) {
            reason = "floating point exception";
            score = 0;
            dump_crash(drcontext, exception_address, exception_code, reason, score);
        }

        if (exception_code == EXCEPTION_BREAKPOINT) {
            reason = "breakpoint";
            score = 25;
            dump_crash(drcontext, exception_address, exception_code, reason, score);
        }

        if(IsBadReadPtr(exception_address, 1)) {
            reason = "oob execution";
            score = 100;
            dump_crash(drcontext, exception_address, exception_code, reason, score);
        }

        instr_t instr;
        instr_init(drcontext, &instr);
        decode(drcontext, exception_address, &instr);

        char buf[100];
        instr_disassemble_to_buffer(drcontext, &instr, buf, 100);
        dr_printf("==== CRASH: %s\n", buf);

        // get crashing instruction
        bool is_ret = instr_is_return(&instr);
        bool is_direct = instr_is_ubr(&instr) || instr_is_cbr(&instr) || instr_is_call_direct(&instr);
        bool is_indirect = instr_is_mbr(&instr);
        bool is_call = instr_is_call(&instr); // this might be covered in other flags

        reg_id_t reg_pc = reg_to_full_width64(DR_REG_NULL);
        reg_id_t reg_stack = reg_to_full_width64(DR_REG_ESP);
        bool pc_tainted = tainted_regs.find(reg_pc) != tainted_regs.end();
        bool stack_tainted = tainted_regs.find(reg_stack) != tainted_regs.end();

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
            dump_crash(drcontext, exception_address, exception_code, reason, score);
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

            dump_crash(drcontext, exception_address, exception_code, reason, score);
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
            dump_crash(drcontext, exception_address, exception_code, reason, score);
        }

        if(mem_read) {
            if(tainted_src) {
                reason = "tainted read";
                score = 75;
            } else {
                reason = "read";
                score = 25;
            }
            dump_crash(drcontext, exception_address, exception_code, reason, score);
        }

        dump_crash(drcontext, exception_address, exception_code, reason, score);
    }
    return true;
}

static void
wrap_pre_ReadFile(void *wrapcxt, OUT void **user_data) {
    dr_fprintf(STDERR, "In wrap_pre_ReadFile\n");
    
    HANDLE hFile = drwrap_get_arg(wrapcxt, 0);
    LPVOID lpBuffer = drwrap_get_arg(wrapcxt, 1);
    DWORD nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 2);
    LPDWORD lpNumberOfBytesRead = (LPDWORD)drwrap_get_arg(wrapcxt, 3);
    
    dr_printf("TAINTED %p\n", lpBuffer);
    taint_mem((app_pc)lpBuffer, nNumberOfBytesToRead);
}

static void
wrap_post_ReadFile(void *wrapcxt, void *user_data) {
    dr_fprintf(STDERR, "In wrap_post_ReadFile\n");
    HANDLE hFile =               (HANDLE)drwrap_get_arg(wrapcxt, 0);
    LPVOID lpBuffer =            drwrap_get_arg(wrapcxt, 1);
    DWORD nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 2);
    LPDWORD lpNumberOfBytesRead = (LPDWORD)drwrap_get_arg(wrapcxt, 3);


    BOOL ok = TRUE; 
    drwrap_set_retval(wrapcxt, &ok); // FIXME
}

static void
module_load_event(void *drcontext, const module_data_t *mod, bool loaded) {
    app_pc towrap = (app_pc) dr_get_proc_address(mod->handle, "ReadFile");
    if (towrap != NULL) {
        dr_flush_region(towrap, 0x1000);
        bool ok = drwrap_wrap(towrap, wrap_pre_ReadFile, wrap_post_ReadFile);
        // bool ok = false;
        if (ok) {
            dr_fprintf(STDERR, "<wrapped ReadFile @ 0x%p\n", towrap);
        } else {
            dr_fprintf(STDERR, "<FAILED to wrap ReadFile @ 0x%p: already wrapped?\n", towrap);
        }
    }
}

void tracer(client_id_t id, int argc, const char *argv[]) {
    /* TRACE TRACE TRACE TRACE TRACE 
    ** TRACE TRACE TRACE TRACE TRACE 
    ** TRACE TRACE TRACE TRACE TRACE 
    ** TRACE TRACE TRACE TRACE TRACE 
    ** TRACE TRACE TRACE TRACE TRACE 
    ** TRACE TRACE TRACE TRACE TRACE 
    ** TRACE TRACE TRACE TRACE TRACE 
    */

    drreg_options_t ops = {sizeof(ops), 3, false};
    dr_set_client_name("DynamoRIO Sample Client 'instrace'",
                       "http://dynamorio.org/issues");
    if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS || !drwrap_init())
        DR_ASSERT(false);

    dr_register_exit_event(event_exit_trace);

    if (!drmgr_register_module_load_event(module_load_event) ||
        !drmgr_register_thread_init_event(event_thread_init) ||
        !drmgr_register_thread_exit_event(event_thread_exit) ||
        !drmgr_register_bb_instrumentation_event(NULL,
                                                 event_app_instruction,
                                                 NULL) ||
        !drmgr_register_exception_event(onexception)) 
    {
        DR_ASSERT(false);
    }


    dr_log(NULL, LOG_ALL, 1, "Client 'instrace' initializing\n");
}

// void coverage(client_id_t id, int argc, const char *argv[]) {
//     /* COVERAGE COVERAGE COVERAGE COVERAGE COVERAGE 
//     ** COVERAGE COVERAGE COVERAGE COVERAGE COVERAGE 
//     ** COVERAGE COVERAGE COVERAGE COVERAGE COVERAGE 
//     ** COVERAGE COVERAGE COVERAGE COVERAGE COVERAGE 
//     ** COVERAGE COVERAGE COVERAGE COVERAGE COVERAGE 
//     ** COVERAGE COVERAGE COVERAGE COVERAGE COVERAGE 
//     ** COVERAGE COVERAGE COVERAGE COVERAGE COVERAGE 
//     */

//     drreg_options_t ops = {sizeof(ops), 3, false};
//     dr_set_client_name("DynamoRIO Sample Client 'instrace'",
//                        "http://dynamorio.org/issues");
//     if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS)
//         DR_ASSERT(false);

//     dr_register_exit_event(event_exit_bb);

//     if (!drmgr_register_thread_init_event(event_thread_init) ||
//         !drmgr_register_thread_exit_event(event_thread_exit_cov) ||
//         !drmgr_register_bb_instrumentation_event(NULL,
//                                                  event_app_bb,
//                                                  NULL) ||
//         !drmgr_register_exception_event(onexception)) 
//     {
//         DR_ASSERT(false);
//     }

//     client_id = id;
//     mutex = dr_mutex_create();

//     tls_idx = drmgr_register_tls_field();
//     DR_ASSERT(tls_idx != -1);

//     if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, INSTRACE_TLS_COUNT, 0))
//         DR_ASSERT(false);

//     dr_log(NULL, LOG_ALL, 1, "Client 'instrace' initializing\n");
// }

// concrete mem
// concrete reg
// processing

// void triage(client_id_t id, int argc, const char *argv[]) {
//     /* TRIAGE TRIAGE TRIAGE TRIAGE TRIAGE 
//     ** TRIAGE TRIAGE TRIAGE TRIAGE TRIAGE 
//     ** TRIAGE TRIAGE TRIAGE TRIAGE TRIAGE 
//     ** TRIAGE TRIAGE TRIAGE TRIAGE TRIAGE 
//     ** TRIAGE TRIAGE TRIAGE TRIAGE TRIAGE 
//     ** TRIAGE TRIAGE TRIAGE TRIAGE TRIAGE 
//     ** TRIAGE TRIAGE TRIAGE TRIAGE TRIAGE 
//     */

//     drreg_options_t ops = {sizeof(ops), 3, false};
//     dr_set_client_name("DynamoRIO Sample Client 'instrace'",
//                        "http://dynamorio.org/issues");
//     if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS)
//         DR_ASSERT(false);

//     triton::API api;
//     api.setArchitecture(triton::arch::ARCH_X86_64);
//     api.addCallback(getConcreteMemCallback);

//     dr_register_exit_event(event_exit);

//     if (!drmgr_register_thread_init_event(event_thread_init) ||
//         !drmgr_register_thread_exit_event(EVENT_THREAD_EXIT) ||
//         !drmgr_register_bb_instrumentation_event(NULL,
//                                                  EVENT_APP,
//                                                  NULL) ||
//         !drmgr_register_exception_event(onexception)) 
//     {
//         DR_ASSERT(false);
//     }

//     client_id = id;
//     mutex = dr_mutex_create();

//     tls_idx = drmgr_register_tls_field();
//     DR_ASSERT(tls_idx != -1);

//     if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, INSTRACE_TLS_COUNT, 0))
//         DR_ASSERT(false);

//     dr_log(NULL, LOG_ALL, 1, "Client 'instrace' initializing\n");
// }

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    tracer(id, argc, argv);
    // coverage(id, argc, argv);
    // triage(id, argc, argv);
}

// DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
//     dr_set_client_name(
//      "Sienna-Locomotive Trace and Triage",
//        "https://github.com/trailofbits/sienna-locomotive/issues");
//     drmgr_init();

//     drmgr_register_bb_instrumentation_event(NULL, bb_insertion, NULL);


//     // instr_length

//     // instr_get_raw_byte

//     // drwrap hooked functions

//     // instr_compute_address_ex

//     // instr_reads_memory

//     // instr_writes_memory

//     // get operands for list of regs?

//     // instr_writes_to_reg

//     // instr_reads_from_reg
// }
