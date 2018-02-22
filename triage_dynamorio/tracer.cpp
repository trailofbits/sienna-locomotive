/* ******************************************************************************
 * Copyright (c) 2011-2017 Google, Inc.  All rights reserved.
 * Copyright (c) 2010 Massachusetts Institute of Technology  All rights reserved.
 * ******************************************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* Code Manipulation API Sample:
 * instrace_simple.c
 *
 * Collects a dynamic instruction trace and dumps it to a text file.
 * This is a simpler (and slower) version of instrace_x86.c.
 *
 * (1) It fills a per-thread-buffer from inlined instrumentation.
 * (2) It calls a clean call to dump the buffer into a file.
 *
 * The trace is a simple text file with each line containing the PC and
 * the opcode of the instruction.
 *
 * This client is a simple implementation of an instruction tracing tool
 * without instrumentation optimization.  It also uses simple absolute PC
 * values and does not separate them into library offsets.
 * Additionally, dumping as text is much slower than dumping as
 * binary.  See instrace_x86.c for a higher-performance sample.
 */

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

#include "Dbghelp.h"

// #include "triton/api.hpp"
// #include "triton/x86Specifications.hpp"

// build ref: https://github.com/firodj/bbtrace/blob/master/CMakeLists.txt

/* Each ins_ref_t describes an executed instruction. */
typedef struct _ins_ref_t {
    app_pc pc;
    int length;
} ins_ref_t;

/* Max number of ins_ref a buffer can have. It should be big enough
 * to hold all entries between clean calls.
 */
#define MAX_NUM_INS_REFS 8192
/* The maximum size of buffer for holding ins_refs. */
#define MEM_BUF_SIZE (sizeof(ins_ref_t) * MAX_NUM_INS_REFS)

/* thread private log file and counter */
typedef struct {
    byte      *seg_base;
    ins_ref_t *buf_base;
    file_t     log;
    FILE      *logf;
    uint64     num_refs;
    ptr_uint_t prev_loc;
} per_thread_t;

static client_id_t client_id;
static void  *mutex;    /* for multithread support */
static uint64 num_refs; /* keep a global instruction reference count */

/* Allocated TLS slot offsets */
enum {
    INSTRACE_TLS_OFFS_BUF_PTR,
    INSTRACE_TLS_COUNT, /* total number of TLS slots allocated */
};

static reg_id_t tls_seg;
static uint     tls_offs;
static int      tls_idx;
#define TLS_SLOT(tls_base, enum_val) (void **)((byte *)(tls_base)+tls_offs+(enum_val))
#define BUF_PTR(tls_base) *(ins_ref_t **)TLS_SLOT(tls_base, INSTRACE_TLS_OFFS_BUF_PTR)

#define MINSERT instrlist_meta_preinsert

std::map<ptr_uint_t, uint64> edge_count;
std::map<ptr_uint_t, uint64> bb_count;

std::set<ptr_uint_t> edge_set;
std::set<ptr_uint_t> bb_set;

static void
instrace(void *drcontext)
{
    per_thread_t *data;
    ins_ref_t *ins_ref, *buf_ptr;

    data    = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    buf_ptr = BUF_PTR(data->seg_base);

    byte addrByte = 0x80;

    for (ins_ref = (ins_ref_t *)data->buf_base; ins_ref < (buf_ptr-1); ins_ref++) {
        /* We use PIFX to avoid leading zeroes and shrink the resulting file. */

        // todo: check length <= 15
        byte length = ins_ref->length;
        fwrite(&length, sizeof(byte), 1, data->logf);

        for(int i = 0; i < ins_ref->length; i++) {
            fwrite((byte *)(ins_ref->pc+i), sizeof(byte), 1, data->logf);
        }
        data->num_refs++;
    }
    
    fwrite(&addrByte, sizeof(byte), 1, data->logf);
    fwrite(&(ins_ref->pc), sizeof(ins_ref->pc), 1, data->logf);

    byte length = ins_ref->length;
    fwrite(&length, sizeof(byte), 1, data->logf);

    for(int i = 0; i < ins_ref->length; i++) {
        fwrite((byte *)(ins_ref->pc+i), sizeof(byte), 1, data->logf);
    }
    data->num_refs++;

    BUF_PTR(data->seg_base) = data->buf_base;
}

static void
covset(void *drcontext) 
{
    per_thread_t *data;
    ins_ref_t *ins_ref, *buf_ptr;
    data    = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    buf_ptr = BUF_PTR(data->seg_base);

    for (ins_ref = (ins_ref_t *)data->buf_base; ins_ref < (buf_ptr-1); ins_ref++) {
        /* We use PIFX to avoid leading zeroes and shrink the resulting file. */
        data->num_refs++;
    }

    ptr_uint_t curr_loc = (ptr_uint_t)ins_ref->pc;
    curr_loc = (curr_loc >> 4) ^ (curr_loc << 8);
    ptr_uint_t edge_id = curr_loc ^ data->prev_loc;
    data->prev_loc = (curr_loc >> 1);

    // edge_count[edge_id]++;
    // bb_count[curr_loc]++;

    edge_set.insert(edge_id);

    data->num_refs++;

    BUF_PTR(data->seg_base) = data->buf_base;
}

/* clean_call dumps the memory reference info to the log file */
static void
clean_call(void)
{
    void *drcontext = dr_get_current_drcontext();
    instrace(drcontext);
}

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
        dr_printf("INS: (%d) %s\n", opcode, buf);
    }
}

static bool
handle_specific(void *drcontext, instr_t *instr) {
    int opcode = instr_get_opcode(instr);
    bool result = false;

    switch(opcode) {
        // pop
        case 20:
            handle_pop(drcontext, instr);
            return true;
        // xor
        case 12:
            result = handle_xor(drcontext, instr);
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

static void
clean_call_bb(void)
{
    void *drcontext = dr_get_current_drcontext();
    covset(drcontext);
}

static void
insert_load_buf_ptr(
    void *drcontext, 
    instrlist_t *ilist, 
    instr_t *where, 
    reg_id_t reg_ptr)
{
    dr_insert_read_raw_tls(
        drcontext, 
        ilist, 
        where, 
        tls_seg,
        tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, 
        reg_ptr);
}

static void
insert_save_pc(
    void *drcontext, 
    instrlist_t *ilist, 
    instr_t *where, 
    reg_id_t base, 
    reg_id_t scratch, 
    app_pc pc)
{
    instrlist_insert_mov_immed_ptrsz(
        drcontext, 
        (ptr_int_t)pc,
        opnd_create_reg(scratch),
        ilist, where, NULL, NULL);

    MINSERT(
        ilist, 
        where,
        XINST_CREATE_store(
            drcontext,
            OPND_CREATE_MEMPTR(base, offsetof(ins_ref_t, pc)),
            opnd_create_reg(scratch)));
}

static void
insert_save_length(
    void *drcontext, 
    instrlist_t *ilist, 
    instr_t *where,
    reg_id_t base, 
    reg_id_t scratch, 
    int length)
{
    scratch = reg_resize_to_opsz(scratch, OPSZ_2);
    MINSERT(
        ilist, 
        where,
        XINST_CREATE_load_int(
            drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_INT16(length)));

    MINSERT(
        ilist, 
        where,
        XINST_CREATE_store_2bytes(
            drcontext,
            OPND_CREATE_MEM16(base, offsetof(ins_ref_t, length)),
            opnd_create_reg(scratch)));
}

static void
insert_update_buf_ptr(
    void *drcontext, 
    instrlist_t *ilist, 
    instr_t *where,
    reg_id_t reg_ptr, 
    int adjust)
{
    MINSERT(
        ilist, 
        where,
        XINST_CREATE_add(
            drcontext,
            opnd_create_reg(reg_ptr),
            OPND_CREATE_INT16(adjust)));

    dr_insert_write_raw_tls(
        drcontext, 
        ilist, 
        where, 
        tls_seg,
        tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, 
        reg_ptr);
}

static void
instrument_instr(void *drcontext, instrlist_t *ilist, instr_t *where)
{
    reg_id_t reg_ptr, reg_tmp;
    if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_ptr) !=
        DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &reg_tmp) !=
        DRREG_SUCCESS) {
        DR_ASSERT(false); /* cannot recover */
        return;
    }

    insert_load_buf_ptr(drcontext, ilist, where, reg_ptr);

    insert_save_pc(
        drcontext, 
        ilist, 
        where, 
        reg_ptr, 
        reg_tmp,
        instr_get_app_pc(where));

    insert_save_length(
        drcontext, 
        ilist, 
        where, 
        reg_ptr, 
        reg_tmp,
       instr_length(drcontext, where));

    insert_update_buf_ptr(drcontext, ilist, where, reg_ptr, sizeof(ins_ref_t));

    if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS)
        DR_ASSERT(false);
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

    instrument_instr(drcontext, bb, instr);

    if (drmgr_is_first_instr(drcontext, instr)
        IF_AARCHXX(&& !instr_is_exclusive_store(instr)))
    {
        dr_insert_clean_call(drcontext, bb, instr, (void *)clean_call, false, 0);
    }

    dr_insert_clean_call(drcontext, bb, instr, propagate_taint, false, 1, 
                OPND_CREATE_INTPTR(instr_get_app_pc(instr)));

    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
event_app_bb(
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

    instrument_instr(drcontext, bb, instr);
    if (drmgr_is_first_instr(drcontext, instr) IF_AARCHXX(&& !instr_is_exclusive_store(instr))) {
        dr_insert_clean_call(drcontext, bb, instr, (void *)clean_call_bb, false, 0);
    }

    return DR_EMIT_DEFAULT;
}

static void
event_thread_init(void *drcontext)
{
    per_thread_t *data = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    DR_ASSERT(data != NULL);
    drmgr_set_tls_field(drcontext, tls_idx, data);

    /* Keep seg_base in a per-thread data structure so we can get the TLS
     * slot and find where the pointer points to in the buffer.
     */
    data->seg_base = (byte *)dr_get_dr_segment_base(tls_seg);
    data->buf_base = (ins_ref_t *)dr_raw_mem_alloc(
        MEM_BUF_SIZE,
        DR_MEMPROT_READ | DR_MEMPROT_WRITE,
        NULL);
    DR_ASSERT(data->seg_base != NULL && data->buf_base != NULL);

    /* put buf_base to TLS as starting buf_ptr */
    BUF_PTR(data->seg_base) = data->buf_base;

    data->num_refs = 0;

    data->prev_loc = 0;

    data->log = log_file_open(
        client_id, 
        drcontext, 
        NULL /* using client lib path */,
        "instrace",
#ifndef WINDOWS
        DR_FILE_CLOSE_ON_FORK |
#endif
        DR_FILE_ALLOW_LARGE);

    data->logf = log_stream_from_file(data->log);
}

static void
event_thread_exit(void *drcontext)
{
    per_thread_t *data;
    instrace(drcontext); /* dump any remaining buffer entries */
    data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    dr_mutex_lock(mutex);
    num_refs += data->num_refs;
    dr_mutex_unlock(mutex);
    log_stream_close(data->logf); /* closes fd too */
    dr_raw_mem_free(data->buf_base, MEM_BUF_SIZE);
    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

static void
event_thread_exit_cov(void *drcontext)
{
    per_thread_t *data;
    covset(drcontext); /* dump any remaining buffer entries */
    data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);

    file_t edge_f = generic_file_open(
        client_id, 
        drcontext, 
        NULL /* using client lib path */,
        "instrace",
        "edges",
#ifndef WINDOWS
        DR_FILE_CLOSE_ON_FORK |
#endif
        DR_FILE_ALLOW_LARGE);

    FILE *edge_fp = log_stream_from_file(edge_f);

    std::set<ptr_uint_t>::iterator edge_it;
    for(edge_it = edge_set.begin(); edge_it != edge_set.end(); edge_it++) {
        fwrite((void *)&(*edge_it), sizeof(byte), sizeof(*edge_it), edge_fp);
    }

    log_stream_close(edge_fp); 

    dr_mutex_lock(mutex);
    num_refs += data->num_refs;
    dr_mutex_unlock(mutex);
    log_stream_close(data->logf); /* closes fd too */
    dr_raw_mem_free(data->buf_base, MEM_BUF_SIZE);
    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

static void
event_exit_bb(void)
{
    dr_log(NULL, LOG_ALL, 1, "Client 'instrace' num refs seen: %lld\n", num_refs);
    if (!dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT))
        DR_ASSERT(false);

    if (!drmgr_unregister_tls_field(tls_idx) ||
        !drmgr_unregister_thread_init_event(event_thread_init) ||
        !drmgr_unregister_thread_exit_event(event_thread_exit_cov) ||
        !drmgr_unregister_bb_insertion_event(event_app_bb) ||
        drreg_exit() != DRREG_SUCCESS)
    {
        DR_ASSERT(false);
    }

    dr_mutex_destroy(mutex);
    drmgr_exit();
}

static void
event_exit_trace(void)
{
    dr_log(NULL, LOG_ALL, 1, "Client 'instrace' num refs seen: %lld\n", num_refs);
    if (!dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT))
        DR_ASSERT(false);

    if (!drmgr_unregister_tls_field(tls_idx) ||
        !drmgr_unregister_thread_init_event(event_thread_init) ||
        !drmgr_unregister_thread_exit_event(event_thread_exit) ||
        !drmgr_unregister_bb_insertion_event(event_app_instruction) ||
        drreg_exit() != DRREG_SUCCESS)
    {
        DR_ASSERT(false);
    }

    dr_mutex_destroy(mutex);
    drmgr_exit();
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
        byte crashByte = 0x82;
        per_thread_t *data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
        
        fwrite(&crashByte, sizeof(byte), 1, data->logf);
        fwrite(&exception_code, sizeof(exception_code), 1, data->logf);
        fwrite(&(excpt->record->ExceptionAddress), sizeof(excpt->record->ExceptionAddress), 1, data->logf);

        dr_exit_process(1);
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

    void *drcontext = drwrap_get_drcontext(wrapcxt);
    per_thread_t *data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);


    dr_printf("TAINTED %p\n", lpBuffer);

    byte taintByte = 0x81;
    fwrite(&taintByte, sizeof(byte), 1, data->logf);
    fwrite(&lpBuffer, sizeof(LPVOID), 1, data->logf);
    uint64 size = 0;
    size = nNumberOfBytesToRead;
    fwrite(&size, sizeof(uint64), 1, data->logf);

    taint_mem((app_pc)lpBuffer, size);
//     // This throws some errors that make me think it won't work in DR
//     file_t dump_f = generic_file_open(
//         client_id, 
//         drcontext, 
//         NULL /* using client lib path */,
//         "instrace",
//         "dump",
// #ifndef WINDOWS
//         DR_FILE_CLOSE_ON_FORK |
// #endif
//         DR_FILE_ALLOW_LARGE);

//     // write minidump
//     HANDLE hProc = GetCurrentProcess();    
//     DWORD procId = GetCurrentProcessId();
//     DWORD type = MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo;
//     if(!MiniDumpWriteDump(hProc, procId, dump_f, (MINIDUMP_TYPE)type, NULL, NULL, NULL)) {
//         dr_printf("minidump failed :(\n");
//         exit(1);
//     }

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

    client_id = id;
    mutex = dr_mutex_create();

    tls_idx = drmgr_register_tls_field();
    DR_ASSERT(tls_idx != -1);

    if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, INSTRACE_TLS_COUNT, 0))
        DR_ASSERT(false);

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
