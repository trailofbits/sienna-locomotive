#include <stdio.h>
#include <map>
#include <set>
#include <fstream>

#include <Windows.h>
#include <Dbghelp.h>
#include <winhttp.h>
#include <Rpc.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drwrap.h"
#include "dr_ir_instr.h"
#include "droption.h"

#include "vendor/picosha2.h"

extern "C" {
    #include "tracer_utils.h"
}

#include "server.hpp"

#include "common/sl2_server_api.hpp"
#include "common/sl2_dr_client.hpp"

static SL2Client   client;
static sl2_conn sl2_conn;
static sl2_exception_ctx trace_exception_ctx;
static void *mutatex;
static bool replay;
static bool no_mutate;
static uint32_t mutate_count;

static std::set<reg_id_t> tainted_regs;
static std::set<app_pc> tainted_mems;

#define LAST_COUNT 5

static int last_call_idx = 0;
static int last_insn_idx = 0;
static app_pc last_calls[LAST_COUNT] = { 0 };
static app_pc last_insns[LAST_COUNT] = { 0 };

static app_pc module_start = 0;
static app_pc module_end = 0;
static size_t baseAddr;

/* Required, which specific call to target */
static droption_t<std::string> op_target(
    DROPTION_SCOPE_CLIENT,
    "t",
    "",
    "target",
    "Specific call to target.");

/* Mostly used to debug if taint tracking is too slow */
static droption_t<unsigned int> op_no_taint(
    DROPTION_SCOPE_CLIENT,
    "nt",
    0,
    "no-taint",
    "Do not do instruction level instrumentation.");

/* Used when replaying a run from the server */
static droption_t<std::string> op_replay(
    DROPTION_SCOPE_CLIENT,
    "r",
    "",
    "replay",
    "The run id for a crash to replay.");

static droption_t<bool> op_no_mutate(
    DROPTION_SCOPE_CLIENT,
    "nm",
    false,
    "no-mutate",
    "Don't use the mutated buffer when replaying.");


/* Currently unused as this runs on 64 bit applications */
static reg_id_t reg_to_full_width32(reg_id_t reg)
{
    switch(reg) {
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

/* Converts a register to full width for taint tracking */
static reg_id_t reg_to_full_width64(reg_id_t reg)
{
    switch(reg) {
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

/* Check whether and operand is tainted */
static bool
is_tainted(void *drcontext, opnd_t opnd)
{
    if (opnd_is_reg(opnd)) {
        /* Check if a register is in tainted_regs */
        reg_id_t reg = opnd_get_reg(opnd);
        reg = reg_to_full_width64(reg);

        if (tainted_regs.find(reg) != tainted_regs.end()) {
            return true;
        }
    }
    else if (opnd_is_memory_reference(opnd)) {
        dr_mcontext_t mc = {sizeof(mc), DR_MC_ALL};
        dr_get_mcontext(drcontext, &mc);
        app_pc addr = opnd_compute_address(opnd, &mc);

        /* Check if a memory region overlaps a tainted address */
        opnd_size_t dr_size = opnd_get_size(opnd);
        uint size = opnd_size_in_bytes(dr_size);
        for (uint i=0; i<size; i++) {
            if (tainted_mems.find(addr+i) != tainted_mems.end()) {
                return true;
            }
        }

        /* Check if a register used in calculating an address is tainted */
        if (opnd_is_base_disp(opnd)) {
            reg_id_t reg_base = opnd_get_base(opnd);
            reg_id_t reg_disp = opnd_get_disp(opnd);
            reg_id_t reg_indx = opnd_get_index(opnd);

            if (reg_base != NULL && tainted_regs.find(reg_to_full_width64(reg_base)) != tainted_regs.end()) {
                return true;
            }

            if (reg_disp != NULL && tainted_regs.find(reg_to_full_width64(reg_disp)) != tainted_regs.end()) {
                return true;
            }

            if (reg_indx != NULL && tainted_regs.find(reg_to_full_width64(reg_indx)) != tainted_regs.end()) {
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

/* Mark a memory address as tainted */
static void
taint_mem(app_pc addr, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        tainted_mems.insert(addr + i);
    }
}

/* Unmark a memory address as tainted */
static bool
untaint_mem(app_pc addr, uint size)
{
    bool untainted = false;
    for (uint i = 0; i < size; i++) {
        size_t n = tainted_mems.erase(addr+i);
        if (n) {
            untainted = true;
        }
        if (untainted) {
            // TODO(ww): Why is this branch here?
        }
    }
    return untainted;
}

/* Mark an operand as tainted. Could be a register or memory reference. */
static void
taint(void *drcontext, opnd_t opnd)
{
    if (opnd_is_reg(opnd)) {
        reg_id_t reg = opnd_get_reg(opnd);
        reg = reg_to_full_width64(reg);

        tainted_regs.insert(reg);

        // char buf[100];
        // opnd_disassemble_to_buffer(drcontext, opnd, buf, 100);
    }
    else if (opnd_is_memory_reference(opnd)) {
        dr_mcontext_t mc = {sizeof(mc), DR_MC_ALL};
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

/* Untaint an operand */
static bool
untaint(void *drcontext, opnd_t opnd)
{
    bool untainted = false;
    if (opnd_is_reg(opnd)) {
        reg_id_t reg = opnd_get_reg(opnd);
        reg = reg_to_full_width64(reg);

        size_t n = tainted_regs.erase(reg);
        if (n) {
            // char buf[100];
            // opnd_disassemble_to_buffer(drcontext, opnd, buf, 100);
            untainted = true;
        }
    }
    else if (opnd_is_memory_reference(opnd)) {
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


/* Handle special case of xor regA, regA - untaint the destination since it's inevitably 0 */
static bool
handle_xor(void *drcontext, instr_t *instr)
{
    bool result = false;
    int src_count = instr_num_srcs(instr);

    if (src_count == 2) {
        opnd_t opnd_0 = instr_get_src(instr, 0);
        opnd_t opnd_1 = instr_get_src(instr, 1);

        if (opnd_is_reg(opnd_0) && opnd_is_reg(opnd_1)) {
            reg_id_t reg_0 = reg_to_full_width64(opnd_get_reg(opnd_0));
            reg_id_t reg_1 = reg_to_full_width64(opnd_get_reg(opnd_1));

            if (reg_0 == reg_1) {
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

/* Handle push and pop by not tainting RSP (included in operands) */
static void
handle_push_pop(void *drcontext, instr_t *instr)
{
    int src_count = instr_num_srcs(instr);
    bool tainted = false;

    // check sources for taint
    for (int i = 0; i < src_count && !tainted; i++) {
        opnd_t opnd = instr_get_src(instr, i);
        tainted |= is_tainted(drcontext, opnd);
    }

    // if tainted
    // taint destinations that aren't rsp
    int dst_count = instr_num_dsts(instr);
    for (int i = 0; i < dst_count && tainted; i++) {
        opnd_t opnd = instr_get_dst(instr, i);

        if (opnd_is_reg(opnd)) {
            reg_id_t reg = opnd_get_reg(opnd);
            reg = reg_to_full_width64(reg);
            if (reg == DR_REG_RSP) {
                continue;
            }
        }

        taint(drcontext, opnd);
    }

    // if not tainted
    // untaint destinations that aren't rsp
    bool untainted = false;
    for (int i = 0; i < dst_count && !tainted; i++) {
        opnd_t opnd = instr_get_dst(instr, i);

        if (opnd_is_reg(opnd)) {
            reg_id_t reg = opnd_get_reg(opnd);
            reg = reg_to_full_width64(reg);
            if (reg == DR_REG_RSP) {
                continue;
            }
        }

        untainted |= untaint(drcontext, opnd);
    }

    // if(tainted | untainted) {
    //     int opcode = instr_get_opcode(instr);
        // char buf[100];
        // instr_disassemble_to_buffer(drcontext, instr, buf, 100);
    // }
}

/* Xchg of a tainted reg and non tainted reg should swap taint */
static bool
handle_xchg(void *drcontext, instr_t *instr)
{
    bool result = false;
    int src_count = instr_num_srcs(instr);

    if (src_count == 2) {
        opnd_t opnd_0 = instr_get_src(instr, 0);
        opnd_t opnd_1 = instr_get_src(instr, 1);

        if (opnd_is_reg(opnd_0) && opnd_is_reg(opnd_1)) {
            reg_id_t reg_0 = reg_to_full_width64(opnd_get_reg(opnd_0));
            reg_id_t reg_1 = reg_to_full_width64(opnd_get_reg(opnd_1));


            bool reg_0_tainted = tainted_regs.find(reg_0) != tainted_regs.end();
            bool reg_1_tainted = tainted_regs.find(reg_1) != tainted_regs.end();

            if (reg_0_tainted && !reg_1_tainted) {
                tainted_regs.erase(reg_0);
                tainted_regs.insert(reg_1);
                result = true;
            }
            else if (reg_1_tainted && !reg_0_tainted) {
                tainted_regs.erase(reg_1);
                tainted_regs.insert(reg_0);
                result = true;
            }
        }
    }

    return result;
}

/* Special cases for tainting / untainting PC */
static bool
handle_branches(void *drcontext, instr_t *instr)
{

    bool is_ret = instr_is_return(instr);
    bool is_direct = instr_is_ubr(instr) || instr_is_cbr(instr) || instr_is_call_direct(instr);
    bool is_indirect = instr_is_mbr(instr);
    bool is_call = instr_is_call(instr);

    if (!is_ret && !is_direct && !is_indirect && !is_call) {
        return false;
    }

    reg_id_t reg_pc = reg_to_full_width64(DR_REG_NULL);
    reg_id_t reg_stack = reg_to_full_width64(DR_REG_ESP);
    bool pc_tainted = tainted_regs.find(reg_pc) != tainted_regs.end();

    bool result = false;
    int src_count = instr_num_srcs(instr);
    int dst_count = instr_num_dsts(instr);

    // call
    if (is_call) {
        if (pc_tainted) {
            // make saved return address tainted
            for (int i = 0; i < dst_count; i++) {
                opnd_t opnd = instr_get_dst(instr, i);
                if (opnd_is_memory_reference(opnd)) {
                    taint(drcontext, opnd);
                    break;
                }
            }
        }
    }

    // direct branch or call
    if (is_direct) {
        if (pc_tainted) {
            // untaint pc
            tainted_regs.erase(reg_pc);
        }
    }

    // indirect branch or call
    if (is_indirect) {
        for (int i = 0; i < src_count; i++) {
            opnd_t opnd = instr_get_src(instr, i);

            if (opnd_is_reg(opnd)) {
                reg_id_t reg = reg_to_full_width64(opnd_get_reg(opnd));
                if (reg != reg_stack && tainted_regs.find(reg) != tainted_regs.end()) {
                    // taint pc
                    tainted_regs.insert(reg_pc);
                }
            }
        }
    }

    /* TODO: check that this taints PC if the tainted address is saved (by the if(is_call)) and restored */
    // ret
    if (is_ret) {
        bool tainted = false;
        for (int i = 0; i < src_count; i++) {
            opnd_t opnd = instr_get_src(instr, i);
            if (is_tainted(drcontext, opnd)) {
                tainted = true;
                break;
            }
        }

        if (tainted) {
            // taint pc
            tainted_regs.insert(reg_pc);
        }
        else {
            // untaint pc
            tainted_regs.erase(reg_pc);
        }
    }

    return true;
}

/* Dispatch to instruction-specific taint handling for things that don't fit the general
    model of tainted operand -> tainted result */
static bool
handle_specific(void *drcontext, instr_t *instr)
{
    int opcode = instr_get_opcode(instr);
    bool result = false;

    // indirect call
    if (handle_branches(drcontext, instr)) {
        return true;
    }

    switch (opcode) {
        case OP_push:
        case OP_pop:
            handle_push_pop(drcontext, instr);
            return true;
        case OP_xor:
            result = handle_xor(drcontext, instr);
            return result;
        case OP_xchg:
            result = handle_xchg(drcontext, instr);
            return result;
        default:
            return false;
    }

}

/* Called on each instruction. Spreads taint from sources to destinations,
    wipes tainted destinations with untainted sources. */
static void
propagate_taint(app_pc pc)
{
    // Store instruction trace
    if (pc > module_start && pc < module_end) {
        last_insns[last_insn_idx] = pc;
        last_insn_idx++;
        last_insn_idx %= LAST_COUNT;
    }

    if (tainted_mems.size() == 0 && tainted_regs.size() == 0) {
        return;
    }

    void *drcontext = dr_get_current_drcontext();
    instr_t instr;
    instr_init(drcontext, &instr);
    decode(drcontext, pc, &instr);

    // Save the count of times we've called this function (if it's a call)
    if (instr_is_call(&instr)) {
        opnd_t target = instr_get_target(&instr);
        if (opnd_is_memory_reference(target)) {
            dr_mcontext_t mc = {sizeof(mc), DR_MC_ALL};
            dr_get_mcontext(drcontext, &mc);
            app_pc addr = opnd_compute_address(target, &mc);

            if (pc > module_start && pc < module_end) {
                last_calls[last_call_idx] = addr;
                last_call_idx++;
                last_call_idx %= LAST_COUNT;
            }
        }
    }

    // if(tainted_mems.size() > 0) {
    //     char buf[100];
    //     instr_disassemble_to_buffer(drcontext, &instr, buf, 100);
    //     dr_printf("%s\n", buf);
    // }

    /* Handle specific instructions */
    if (handle_specific(drcontext, &instr)) {
        instr_free(drcontext, &instr);
        return;
    }

    /* Check if sources are tainted */
    int src_count = instr_num_srcs(&instr);
    bool tainted = false;

    for (int i=0; i<src_count && !tainted; i++) {
        opnd_t opnd = instr_get_src(&instr, i);
        tainted |= is_tainted(drcontext, opnd);
    }

    /* If tainted sources, taint destinations */
    int dst_count = instr_num_dsts(&instr);
    for (int i=0; i<dst_count && tainted; i++) {
        opnd_t opnd = instr_get_dst(&instr, i);
        taint(drcontext, opnd);
    }

    /* If not tainted sources, untaint destinations*/
    bool untainted = false;
    for (int i=0; i<dst_count && !tainted; i++) {
        opnd_t opnd = instr_get_dst(&instr, i);
        untainted |= untaint(drcontext, opnd);
    }

    // if(tainted | untainted) {
    //     int opcode = instr_get_opcode(&instr);
    // }

    instr_free(drcontext, &instr);
}

/* Called upon basic block insertion with each individual instruction as an argument.
    Inserts a clean call to propagate_taint before every instruction */
static dr_emit_flags_t
on_bb_instrument(
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

    /* Clean call propagate taint on each instruction. Should be side-effect free
        http://dynamorio.org/docs/dr__ir__utils_8h.html#ae7b7bd1e750b8a24ebf401fb6a6d6d5e */
    // TODO(ww): Replace this with instruction injection for performance?
    dr_insert_clean_call(drcontext, bb, instr, propagate_taint, false, 1,
                OPND_CREATE_INTPTR(instr_get_app_pc(instr)));

    return DR_EMIT_DEFAULT;
}

static void
on_thread_init(void *drcontext)
{

}

static void
on_thread_exit(void *drcontext)
{

}

/* Clean up registered callbacks before exiting */
static void
on_dr_exit(void)
{
    if (!op_no_taint.get_value()) {
        if (!drmgr_unregister_bb_insertion_event(on_bb_instrument)) {
            DR_ASSERT(false);
        }
    }

    if (!drmgr_unregister_thread_init_event(on_thread_init) ||
        !drmgr_unregister_thread_exit_event(on_thread_exit) ||
        drreg_exit() != DRREG_SUCCESS)
    {
        DR_ASSERT(false);
    }

    sl2_conn_close(&sl2_conn);

    drmgr_exit();
}

/* Debug functionality. If you need to use it, add the relevant print statements */
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
    for (reg_it = tainted_regs.begin(); reg_it != tainted_regs.end(); reg_it++) {
        // TODO(ww): Implement.
    }

    std::set<app_pc>::iterator mem_it;
    for (mem_it = tainted_mems.begin(); mem_it != tainted_mems.end(); mem_it++) {
        // TODO(ww): Implement.
    }

    for (int i = 0; i < 16; i++) {
        bool tainted = tainted_regs.find(regs[i]) != tainted_regs.end();
        dr_mcontext_t mc = {sizeof(mc),DR_MC_ALL};
        dr_get_mcontext(drcontext, &mc);
        if (tainted) {
            // TODO(ww): Implement.
        }
        else {
            // TODO(ww): Implement.
        }
    }

    bool tainted = tainted_regs.find(DR_REG_NULL) != tainted_regs.end();
    if (tainted) {
        // TODO(ww): Implement.
    }
    else {
        // TODO(ww): Implement.
    }
}

std::string
exception_to_string(DWORD exception_code)
{
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

/* Get crash info as JSON for dumping to stderr */
std::string
dump_json(void *drcontext, uint8_t score, std::string reason, dr_exception_t *excpt, std::string disassembly)
{
    DWORD exception_code = excpt->record->ExceptionCode;
    app_pc exception_address = (app_pc)excpt->record->ExceptionAddress;

    json j;

    j["score"] = score;
    j["reason"] = reason;
    j["exception"] = exception_to_string(exception_code);
    j["location"] = (uint64) exception_address;
    j["instruction"] = disassembly;

    j["regs"] = json::array();
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

    for (int i = 0; i < 16; i++) {
        bool tainted = tainted_regs.find(regs[i]) != tainted_regs.end();
        json reg = {{"reg", get_register_name(regs[i])},
                    {"value", reg_get_value(regs[i], excpt->mcontext)},
                    {"tainted", tainted}};
        j["regs"].push_back(reg);
    }

    bool tainted = tainted_regs.find(DR_REG_NULL) != tainted_regs.end();
    json rip = {{"reg", "rip"},
                {"value", (uint64) exception_address},
                {"tainted", tainted}};
    j["regs"].push_back(rip);

    j["last_calls"] = json::array();
    for (int i = 0; i < LAST_COUNT; i++) {
        int idx = last_call_idx + i;
        idx %= LAST_COUNT;
        j["last_calls"].push_back((uint64)last_calls[idx]);
    }

    j["last_insns"] = json::array();
    for (int i = 0; i < LAST_COUNT; i++) {
        int idx = last_insn_idx + i;
        idx %= LAST_COUNT;
        j["last_insns"].push_back((uint64)last_insns[idx]);
    }

    j["tainted_addrs"] = json::array();
    if (tainted_mems.size() > 0) {
        std::set<app_pc>::iterator mit = tainted_mems.begin();
        uint64_t start = (uint64_t) *mit;
        uint64_t size = 1;

        mit++;
        for (; mit != tainted_mems.end(); mit++) {
            uint64_t curr = (uint64_t) *mit;
            if (curr > (start + size)) {
              json addr = {{"start", start}, {"size", size}};
              j["tainted_addrs"].push_back(addr);

                start = curr;
                size = 0;
            }
            size++;
        }

        json addr = {{"start", start}, {"size", size}};
        j["tainted_addrs"].push_back(addr);
    }

    return j.dump();
}

/* Get Run ID and dump crash info into JSON file in the run folder. */
static void
dump_crash(void *drcontext, dr_exception_t *excpt, std::string reason, uint8_t score, std::string disassembly)
{
    sl2_crash_paths crash_paths = {0};
    std::string crash_json = dump_json(drcontext, score, reason, excpt, disassembly);

    if (replay) {
        sl2_conn_request_crash_paths(&sl2_conn, &crash_paths);

        HANDLE hCrashFile = CreateFile(crash_paths.crash_path, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

        if (hCrashFile == INVALID_HANDLE_VALUE) {
            SL2_DR_DEBUG("tracer#dump_crash: could not open the crash file (%x)\n", GetLastError());
            exit(1);
        }

        DWORD txsize;
        if (!WriteFile(hCrashFile, crash_json.c_str(), (DWORD) crash_json.length(), &txsize, NULL)) {
            SL2_DR_DEBUG("tracer#dump_crash: could not write to the crash file (%x)\n", GetLastError());
            exit(1);
        }

        CloseHandle(hCrashFile);

        HANDLE hDumpFile = CreateFile(crash_paths.mem_dump_path, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

        if (hDumpFile == INVALID_HANDLE_VALUE) {
            SL2_DR_DEBUG("tracer#dump_crash: could not open the dump file (%x)\n", GetLastError());
        }

        EXCEPTION_POINTERS exception_pointers = {0};
        MINIDUMP_EXCEPTION_INFORMATION mdump_info = {0};

        exception_pointers.ExceptionRecord = &(trace_exception_ctx.record);
        exception_pointers.ContextRecord = &(trace_exception_ctx.thread_ctx);

        mdump_info.ThreadId = trace_exception_ctx.thread_id;
        mdump_info.ExceptionPointers = &exception_pointers;
        mdump_info.ClientPointers = true;

        // NOTE(ww): Switching back to the application's state is necessary, as we don't want
        // parts of the instrumentation showing up in our memory dump.
        dr_switch_to_app_state(drcontext);

        MiniDumpWriteDump(
            GetCurrentProcess(),
            GetCurrentProcessId(),
            hDumpFile,
            MiniDumpWithFullMemory,
            &mdump_info,
            NULL, NULL);

        dr_switch_to_dr_state(drcontext);

        CloseHandle(hDumpFile);
    }

    dr_exit_process(1);
}

/* Scoring function. Checks exception code, then checks taint state in order to calculate the severity score */
static bool
on_exception(void *drcontext, dr_exception_t *excpt)
{
    DWORD exception_code = excpt->record->ExceptionCode;

    dr_switch_to_app_state(drcontext);
    trace_exception_ctx.thread_id = GetCurrentThreadId();
    dr_mcontext_to_context(&(trace_exception_ctx.thread_ctx), excpt->mcontext);
    dr_switch_to_dr_state(drcontext);

    // Make our own copy of the exception record.
    memcpy(&(trace_exception_ctx.record), excpt->record, sizeof(EXCEPTION_RECORD));

    reg_id_t reg_pc = reg_to_full_width64(DR_REG_NULL);
    reg_id_t reg_stack = reg_to_full_width64(DR_REG_ESP);
    bool pc_tainted = tainted_regs.find(reg_pc) != tainted_regs.end();
    bool stack_tainted = tainted_regs.find(reg_stack) != tainted_regs.end();

    // catch-all result
    app_pc exception_address = (app_pc)(excpt->record->ExceptionAddress);
    std::string reason = "unknown";
    uint8_t score = 50;
    std::string disassembly = "";

    // TODO - remove use of IsBadReadPtr
    // https://msdn.microsoft.com/en-us/library/windows/desktop/aa366713(v=vs.85).aspx
    if (IsBadReadPtr(exception_address, 1))
    {
        if (pc_tainted) {
            reason = "oob execution tainted pc";
            score = 100;
        }
        else {
            reason = "oob execution";
            score = 50;
        }
        dump_crash(drcontext, excpt, reason, score, disassembly);
    }

    instr_t instr;
    // TODO: this isn't instr_freed because of all the early returns
    // it shouldn't hurt though
    instr_init(drcontext, &instr);
    decode(drcontext, exception_address, &instr);
    char buf[100];
    instr_disassemble_to_buffer(drcontext, &instr, buf, 100);

    disassembly = buf;

    // check exception code - illegal instructions are bad
    if (exception_code == EXCEPTION_ILLEGAL_INSTRUCTION) {
        if (pc_tainted) {
            reason = "illegal instruction tainted pc";
            score = 100;
        }
        else {
            reason = "illegal instruction";
            score = 50;
        }
        dump_crash(drcontext, excpt, reason, score, disassembly);
    }

    // Divide by zero is probably not bad
    if (exception_code == EXCEPTION_INT_DIVIDE_BY_ZERO) {
        reason = "floating point exception";
        score = 0;
        dump_crash(drcontext, excpt, reason, score, disassembly);
    }

    // Breakpoints - could indicate we're executing non-instructions?
    // TODO figure out if 25 points makes sense
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


    for (int i = 0; i < src_count; i++) {
        opnd_t opnd = instr_get_src(&instr, i);
        tainted_src |= is_tainted(drcontext, opnd);
    }

    for (int i = 0; i < dst_count; i++) {
        opnd_t opnd = instr_get_dst(&instr, i);
        tainted_dst |= is_tainted(drcontext, opnd);
    }

    // Check if the crash resulted from an invalid memory write
    // usually EXCEPTION_ACCESS_VIOLATION
    if (mem_write) {
        // If what we're writing or where we're writing it to are potentially attacker controlled, that's worse than if
        // it's just a normal invalid write
        if (tainted_src || tainted_dst) {
            reason = "tainted write";
            score = 75;
        }
        else {
            reason = "write";
            score = 50;
        }

        dump_crash(drcontext, excpt, reason, score, disassembly);
    }

    // ditto, but for invalid reads
    if (mem_read) {
        // TODO - do we need to think about tainted destination addresses?
        if (tainted_src) {
            reason = "tainted read";
            score = 75;
        }
        else {
            reason = "read";
            score = 25;
        }

        dump_crash(drcontext, excpt, reason, score, disassembly);
    }

    dump_crash(drcontext, excpt, reason, score, disassembly);

    return true;
}

/*
    The next three functions are used to intercept __fastfail, which Windows
    provides to allow processes to request immediate termination.

    To get around this, we tell the target that __fastfail isn't avaiable
    by intercepting IsProcessorFeaturePresent (which we hope they check).

    We then hope that they craft an exception record instead and send it
    to UnhandledException, where we intercept it and forward it to our
    exception handler.

    If the target decides to do neither of these, we still miss the exception.

    This trick was cribbed from WinAFL:
    https://github.com/ivanfratric/winafl/blob/73c7b41/winafl.c#L600

    NOTE(ww): These functions are duplicated across the fuzzer and the tracer.
    Keep them synced!
*/

void wrap_pre_IsProcessorFeaturePresent(void *wrapcxt, OUT void **user_data)
{
    DWORD feature = (DWORD) drwrap_get_arg(wrapcxt, 0);
    *user_data = (void *) feature;
}

void wrap_post_IsProcessorFeaturePresent(void *wrapcxt, void *user_data)
{
    DWORD feature = (DWORD) user_data;

    if (feature == PF_FASTFAIL_AVAILABLE) {
        SL2_DR_DEBUG("wrap_post_IsProcessorFeaturePresent: got PF_FASTFAIL_AVAILABLE request, masking\n");
        drwrap_set_retval(wrapcxt, (void *) 0);
    }
}

void wrap_pre_UnhandledExceptionFilter(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("wrap_pre_UnhandledExceptionFilter: stealing unhandled exception\n");

    EXCEPTION_POINTERS *exception = (EXCEPTION_POINTERS *) drwrap_get_arg(wrapcxt, 0);
    dr_exception_t excpt = {0};

    excpt.record = exception->ExceptionRecord;
    on_exception(drwrap_get_drcontext(wrapcxt), &excpt);
}

/*
    We also intercept VerifierStopMessage and VerifierStopMessageEx,
    which are supplied by Application Verifier for the purpose of catching
    heap corruptions.
*/

static void wrap_pre_VerifierStopMessage(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("wrap_pre_VerifierStopMessage: stealing unhandled exception\n");

    EXCEPTION_RECORD record = {0};
    record.ExceptionCode = STATUS_HEAP_CORRUPTION;

    dr_exception_t excpt = {0};
    excpt.record = &record;

    on_exception(drwrap_get_drcontext(wrapcxt), &excpt);
}

/*
*
  Large block of pre-function callbacks that collect metadata about the target call
*
*/

static void
wrap_pre_ReadEventLog(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_ReadEventLog>\n");
    HANDLE hEventLog                 = (HANDLE)drwrap_get_arg(wrapcxt, 0);
    DWORD  dwReadFlags               = (DWORD)drwrap_get_arg(wrapcxt, 1);
    DWORD  dwRecordOffset            = (DWORD)drwrap_get_arg(wrapcxt, 2);
    void   *lpBuffer                 = (void *)drwrap_get_arg(wrapcxt, 3);
    DWORD  nNumberOfBytesToRead      = (DWORD)drwrap_get_arg(wrapcxt, 4);
    DWORD  *pnBytesRead              = (DWORD *)drwrap_get_arg(wrapcxt, 5);
    DWORD  *pnMinNumberOfBytesNeeded = (DWORD *)drwrap_get_arg(wrapcxt, 6);

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->lpBuffer             = lpBuffer;
    info->nNumberOfBytesToRead = nNumberOfBytesToRead;
    info->function             = Function::ReadEventLog;
    info->retAddrOffset        = (size_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}

static void
wrap_pre_RegQueryValueEx(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_RegQueryValueEx>\n");
    HKEY hKey         = (HKEY)drwrap_get_arg(wrapcxt, 0);
    char *lpValueName = (char *)drwrap_get_arg(wrapcxt, 1);
    DWORD *lpReserved = (DWORD *)drwrap_get_arg(wrapcxt, 2);
    DWORD *lpType     = (DWORD *)drwrap_get_arg(wrapcxt, 3);
    BYTE *lpData      = (BYTE *)drwrap_get_arg(wrapcxt, 4);
    DWORD *lpcbData   = (DWORD *)drwrap_get_arg(wrapcxt, 5);

    if (lpData != NULL && lpcbData != NULL) {
        *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
        client_read_info *info = (client_read_info *) *user_data;

        info->lpBuffer             = lpData;
        info->nNumberOfBytesToRead = *lpcbData;
        info->function             = Function::RegQueryValueEx;
        info->retAddrOffset        = (size_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
        info->argHash              = NULL;
    }
    else {
        *user_data = NULL;
    }
}

static void
wrap_pre_WinHttpWebSocketReceive(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_WinHttpWebSocketReceive>\n");
    HINTERNET hRequest                          = (HINTERNET)drwrap_get_arg(wrapcxt, 0);
    void *pvBuffer                              = drwrap_get_arg(wrapcxt, 1);
    DWORD dwBufferLength                        = (DWORD)drwrap_get_arg(wrapcxt, 2);
    DWORD *pdwBytesRead                         = (DWORD *)drwrap_get_arg(wrapcxt, 3);
    WINHTTP_WEB_SOCKET_BUFFER_TYPE peBufferType = (WINHTTP_WEB_SOCKET_BUFFER_TYPE)(int)drwrap_get_arg(wrapcxt, 3);

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->lpBuffer = pvBuffer;
    info->nNumberOfBytesToRead = dwBufferLength;
    info->function = Function::WinHttpWebSocketReceive;
    info->retAddrOffset = (size_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}

static void
wrap_pre_InternetReadFile(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_InternetReadFile>\n");
    HINTERNET hFile             = (HINTERNET)drwrap_get_arg(wrapcxt, 0);
    void *lpBuffer              = drwrap_get_arg(wrapcxt, 1);
    DWORD nNumberOfBytesToRead  = (DWORD)drwrap_get_arg(wrapcxt, 2);
    DWORD *lpNumberOfBytesRead  = (DWORD*)drwrap_get_arg(wrapcxt, 3);

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->lpBuffer             = lpBuffer;
    info->nNumberOfBytesToRead = nNumberOfBytesToRead;
    info->function             = Function::InternetReadFile;
    info->retAddrOffset        = (size_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}

static void
wrap_pre_WinHttpReadData(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_WinHttpReadData>\n");
    HINTERNET hRequest          = (HINTERNET)drwrap_get_arg(wrapcxt, 0);
    void *lpBuffer              = drwrap_get_arg(wrapcxt, 1);
    DWORD nNumberOfBytesToRead  = (DWORD)drwrap_get_arg(wrapcxt, 2);
    DWORD *lpNumberOfBytesRead  = (DWORD*)drwrap_get_arg(wrapcxt, 3);

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->lpBuffer             = lpBuffer;
    info->nNumberOfBytesToRead = nNumberOfBytesToRead;
    info->function             = Function::WinHttpReadData;
    info->retAddrOffset        = (size_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}

static void
wrap_pre_recv(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_recv>\n");
    SOCKET s  = (SOCKET)drwrap_get_arg(wrapcxt, 0);
    char *buf = (char *)drwrap_get_arg(wrapcxt, 1);
    int len   = (int)drwrap_get_arg(wrapcxt, 2);
    int flags = (int)drwrap_get_arg(wrapcxt, 3);

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->lpBuffer             = buf;
    info->nNumberOfBytesToRead = len;
    info->function             = Function::recv;
    info->retAddrOffset        = (size_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}

static void
wrap_pre_ReadFile(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_ReadFile>\n");
    HANDLE hFile                = drwrap_get_arg(wrapcxt, 0);
    void *lpBuffer              = drwrap_get_arg(wrapcxt, 1);
    DWORD nNumberOfBytesToRead  = (DWORD)drwrap_get_arg(wrapcxt, 2);
    DWORD *lpNumberOfBytesRead  = (DWORD*)drwrap_get_arg(wrapcxt, 3);

    fileArgHash fStruct = {0};

    LARGE_INTEGER offset = {0};
    LARGE_INTEGER position = {0};
    SetFilePointerEx(hFile, offset, &position, FILE_CURRENT);

    GetFinalPathNameByHandle(hFile, fStruct.fileName, MAX_PATH, FILE_NAME_NORMALIZED);
    fStruct.position = position.QuadPart;
    fStruct.readSize = nNumberOfBytesToRead;

    std::vector<unsigned char> blob_vec((unsigned char *) &fStruct,
        ((unsigned char *) &fStruct) + sizeof(fileArgHash));
    std::string hash_str;
    picosha2::hash256_hex_string(blob_vec, hash_str);

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->lpBuffer             = lpBuffer;
    info->nNumberOfBytesToRead = nNumberOfBytesToRead;
    info->function             = Function::ReadFile;
    info->retAddrOffset        = (size_t) drwrap_get_retaddr(wrapcxt) - baseAddr;

    info->argHash = (char *) dr_thread_alloc(drwrap_get_drcontext(wrapcxt), SL2_HASH_LEN + 1);
    memset(info->argHash, 0, SL2_HASH_LEN + 1);
    memcpy(info->argHash, hash_str.c_str(), SL2_HASH_LEN);
}

static void
wrap_pre_fread_s(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_fread_s>\n");
    void *buffer = (void *)drwrap_get_arg(wrapcxt, 0);
    size_t size  = (size_t)drwrap_get_arg(wrapcxt, 2);
    size_t count = (size_t)drwrap_get_arg(wrapcxt, 3);

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::fread;
    info->lpBuffer             = buffer;
    info->nNumberOfBytesToRead = size * count;
    info->retAddrOffset        = (size_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}

static void
wrap_pre_fread(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_fread>\n");
    void *buffer = (void *)drwrap_get_arg(wrapcxt, 0);
    size_t size  = (size_t)drwrap_get_arg(wrapcxt, 1);
    size_t count = (size_t)drwrap_get_arg(wrapcxt, 2);

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::fread;
    info->lpBuffer             = buffer;
    info->nNumberOfBytesToRead = size * count;
    info->retAddrOffset        = (size_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}

/* Called after each targeted function to replay mutation and mark bytes as tainted */
static void
wrap_post_Generic(void *wrapcxt, void *user_data)
{
    SL2_DR_DEBUG("<in wrap_post_Generic>\n");
    if (user_data == NULL) {
        return;
    }

    client_read_info *info = (client_read_info *) user_data;

    // Grab stored metadata
    void *lpBuffer              = info->lpBuffer;
    size_t nNumberOfBytesToRead = info->nNumberOfBytesToRead;
    Function function           = info->function;
    info->retAddrOffset         = (size_t) drwrap_get_retaddr(wrapcxt) - baseAddr;


    // Identify whether this is the function we want to target
    bool targeted = client.isFunctionTargeted( function, info );
    client.incrementCallCountForFunction(function);

    // Mark the targeted memory as tainted
    if (targeted) {
        taint_mem((app_pc)lpBuffer, nNumberOfBytesToRead);
    }

    // Talk to the server, get the stored mutation from the fuzzing run, and write it into memory.
    if (replay && targeted) {
        dr_mutex_lock(mutatex);

        if (no_mutate) {
            SL2_DR_DEBUG("user requested replay WITHOUT mutation!\n");
        }
        else {
            sl2_conn_request_replay(&sl2_conn, mutate_count, nNumberOfBytesToRead, lpBuffer);
        }

        mutate_count++;

        dr_mutex_unlock(mutatex);
    }

    if (info->argHash) {
        dr_thread_free(drwrap_get_drcontext(wrapcxt), info->argHash, SL2_HASH_LEN + 1);
    }

    dr_thread_free(drwrap_get_drcontext(wrapcxt), info, sizeof(client_read_info));
}

/* Register function pre/post callbacks in each module */
static void
on_module_load(void *drcontext, const module_data_t *mod, bool loaded)
{
    if (!strcmp(dr_get_application_name(), dr_module_preferred_name(mod))) {
      baseAddr = (size_t) mod->start;
    }

    const char *mod_name = dr_module_preferred_name(mod);
    app_pc towrap;

    std::map<char *, SL2_PRE_PROTO> toHookPre;
    SL2_PRE_HOOK1(toHookPre, ReadFile);
    SL2_PRE_HOOK1(toHookPre, InternetReadFile);
    SL2_PRE_HOOK1(toHookPre, ReadEventLog);
    SL2_PRE_HOOK2(toHookPre, RegQueryValueExW, RegQueryValueEx);
    SL2_PRE_HOOK2(toHookPre, RegQueryValueExA, RegQueryValueEx);
    SL2_PRE_HOOK1(toHookPre, WinHttpWebSocketReceive);
    SL2_PRE_HOOK1(toHookPre, WinHttpReadData);
    SL2_PRE_HOOK1(toHookPre, recv);
    SL2_PRE_HOOK1(toHookPre, fread_s);
    SL2_PRE_HOOK1(toHookPre, fread);

    std::map<char *, SL2_POST_PROTO> toHookPost;
    SL2_POST_HOOK2(toHookPost, ReadFile, Generic);
    SL2_POST_HOOK2(toHookPost, InternetReadFile, Generic);
    SL2_POST_HOOK2(toHookPost, ReadEventLog, Generic);
    SL2_POST_HOOK2(toHookPost, RegQueryValueExW, Generic);
    SL2_POST_HOOK2(toHookPost, RegQueryValueExA, Generic);
    SL2_POST_HOOK2(toHookPost, WinHttpWebSocketReceive, Generic);
    SL2_POST_HOOK2(toHookPost, WinHttpReadData, Generic);
    SL2_POST_HOOK2(toHookPost, recv, Generic);
    SL2_POST_HOOK2(toHookPost, fread_s, Generic);
    SL2_POST_HOOK2(toHookPost, fread, Generic);

    // Wrap IsProcessorFeaturePresent and UnhandledExceptionFilter to prevent
    // __fastfail from circumventing our exception tracking. See the comment
    // above wrap_pre_IsProcessorFeaturePresent for more information.
    if (STREQI(mod_name, "KERNELBASE.DLL")) {
        SL2_DR_DEBUG("loading __fastfail mitigations\n");

        towrap = (app_pc) dr_get_proc_address(mod->handle, "IsProcessorFeaturePresent");
        drwrap_wrap(towrap, wrap_pre_IsProcessorFeaturePresent, wrap_post_IsProcessorFeaturePresent);

        towrap = (app_pc) dr_get_proc_address(mod->handle, "UnhandledExceptionFilter");
        drwrap_wrap(towrap, wrap_pre_UnhandledExceptionFilter, NULL);
    }

    // Wrap VerifierStopMessage and VerifierStopMessageEx, which are apparently
    // used in AppVerifier to register heap corruptions.
    //
    // NOTE(ww): I haven't seen these in the wild, but WinAFL wraps
    // VerifierStopMessage and VerifierStopMessageEx is probably
    // just a newer version of the former.
    if (STREQ(mod_name, "VERIFIER.DLL"))
    {
        SL2_DR_DEBUG("loading Application Verifier mitigations\n");

        towrap = (app_pc) dr_get_proc_address(mod->handle, "VerifierStopMessage");
        drwrap_wrap(towrap, wrap_pre_VerifierStopMessage, NULL);

        towrap = (app_pc) dr_get_proc_address(mod->handle, "VerifierStopMessageEx");
        drwrap_wrap(towrap, wrap_pre_VerifierStopMessage, NULL);
    }

    /* assume our target executable is an exe */
    if (strstr(mod_name, ".exe") != NULL) {
        module_start = mod->start; // TODO evaluate us of dr_get_application_name above
        module_end = module_start + mod->module_internal_size;
    }

    // when a module is loaded, iterate its functions looking for matches in toHookPre
    std::map<char *, SL2_PRE_PROTO>::iterator it;
    for (it = toHookPre.begin(); it != toHookPre.end(); it++) {
        char *functionName = it->first;
        bool hook = false;

        // Look for function matching the target specified on the command line
        for (targetFunction t : client.parsedJson) {
            if (t.selected && STREQ(t.functionName.c_str(), functionName)){
                hook = true;
            }
            else if (t.selected && (STREQ(functionName, "RegQueryValueExW") || STREQ(functionName, "RegQueryValueExA"))) {
                if (!STREQ(t.functionName.c_str(), "RegQueryValueEx")) {
                  hook = false;
                }
            }
        }

        if (!hook)
          continue;

        void(__cdecl *hookFunctionPre)(void *, void **);
        hookFunctionPre = it->second;
        void(__cdecl *hookFunctionPost)(void *, void *);
        hookFunctionPost = NULL;

        // if we have a post hook function, use it
        // TODO(ww): Why do we do this, instead of just assigning above?
        if (toHookPost.find(functionName) != toHookPost.end()) {
            hookFunctionPost = toHookPost[functionName];
        }

        // find target function in module
        towrap = (app_pc) dr_get_proc_address(mod->handle, functionName);

        // TODO(ww): Consolidate this between the wizard, fuzzer, and tracer.
        if (STREQ(functionName, "ReadFile")) {
            if (!STREQI(mod_name, "KERNELBASE.dll") != 0) {
                continue;
            }
        }

        if (STREQ(functionName, "RegQueryValueExA") || STREQ(functionName, "RegQueryValueExW")) {
            if (!STREQI(mod_name, "KERNELBASE.dll") != 0) {
                continue;
            }
        }

        if (STREQ(functionName, "fread") || STREQ(functionName, "fread_s")) {
            if (!STREQI(mod_name, "UCRTBASE.DLL")) {
                continue;
            }
        }

        // if the function was found, wrap it
        if (towrap != NULL) {
            dr_flush_region(towrap, 0x1000);
            bool ok = drwrap_wrap(towrap, hookFunctionPre, hookFunctionPost);
            // bool ok = false;
            if (ok) {
                SL2_DR_DEBUG("<wrapped %s @ 0x%p>\n", functionName, towrap);
            }
            else {
                SL2_DR_DEBUG("<FAILED to wrap %s @ 0x%p: already wrapped?>\n", functionName, towrap);
            }
        }
    }
}

// register callbacks
void tracer(client_id_t id, int argc, const char *argv[])
{
    drreg_options_t ops = {sizeof(ops), 3, false};
    dr_set_client_name("Tracer",
                       "https://github.com/trailofbits/sienna-locomotive");

    if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS || !drwrap_init())
        DR_ASSERT(false);

    replay = false;
    mutate_count = 0;

    std::string run_id_s = op_replay.get_value();
    UUID run_id;

    if (run_id_s.length() > 0) {
        replay = true;
    }

    no_mutate = op_no_mutate.get_value();

    sl2_string_to_uuid(run_id_s.c_str(), &run_id);
    sl2_conn_assign_run_id(&sl2_conn, run_id);

    mutatex = dr_mutex_create();
    dr_register_exit_event(on_dr_exit);

    // If taint tracing is enabled, register the propagate_taint callback
    if (!op_no_taint.get_value()) {
        // http://dynamorio.org/docs/group__drmgr.html#ga83a5fc96944e10bd7356e0c492c93966
        if (!drmgr_register_bb_instrumentation_event(
                                                NULL,
                                                on_bb_instrument,
                                                NULL))
        {
            DR_ASSERT(false);
        }
    }

    if (!drmgr_register_module_load_event(on_module_load) ||
        !drmgr_register_thread_init_event(on_thread_init) ||
        !drmgr_register_thread_exit_event(on_thread_exit) ||
        !drmgr_register_exception_event(on_exception))
    {
        DR_ASSERT(false);
    }

    dr_log(NULL, DR_LOG_ALL, 1, "Client 'instrace' initializing\n");
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    // parse client options
    std::string parse_err;
    int last_idx = 0;
    if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, &parse_err, &last_idx)) {
        SL2_DR_DEBUG("tracer#main: usage error: %s", parse_err.c_str());
        dr_abort();
    }

    // target is mandatory
    std::string target = op_target.get_value();
    if (target == "") {
        SL2_DR_DEBUG("tracer#main: ERROR: arg -t (target) required");
        dr_abort();
    }

    if (!client.loadJson(target)) {
        SL2_DR_DEBUG("Failed to load targets!\n");
        dr_abort();
    }

    // NOTE(ww): We open the client's connection to the server here,
    // but the client isn't ready to use until it's been given a run ID.
    // See inside of `tracer` for that.
    if (sl2_conn_open(&sl2_conn) != SL2Response::OK) {
        SL2_DR_DEBUG("ERROR: Couldn't open a connection to the server!\n");
        dr_abort();
    }

    tracer(id, argc, argv);
}
