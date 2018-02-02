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
extern "C" {
#include "utils.h"
}

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

    for (ins_ref = (ins_ref_t *)data->buf_base; ins_ref < (buf_ptr-1); ins_ref++) {
        /* We use PIFX to avoid leading zeroes and shrink the resulting file. */
        fprintf(data->logf, "INS(", (ptr_uint_t)ins_ref->pc);
        fprintf(data->logf, PIFX",", (ptr_uint_t)ins_ref->pc);
        fprintf(data->logf, "0x%02x,\"", (ptr_uint_t)ins_ref->length);
        for(int i = 0; i < ins_ref->length; i++) {
            fprintf(data->logf, "\\x%02x", *(byte *)(ins_ref->pc+i));
        }
        fprintf(data->logf, "\")\n");
        data->num_refs++;
    }

    fprintf(data->logf, "\n");

    ptr_uint_t curr_loc = (ptr_uint_t)ins_ref->pc;
    curr_loc = (curr_loc >> 4) ^ (curr_loc << 8);
    ptr_uint_t edge_id = curr_loc ^ data->prev_loc;
    data->prev_loc = (curr_loc >> 1);

    fprintf(data->logf, "EDGE(");
    fprintf(data->logf, PIFX")\n", edge_id);

    fprintf(data->logf, "BB(");
    fprintf(data->logf, PIFX")\n", (ptr_uint_t)ins_ref->pc);

    fprintf(data->logf, "INS(", (ptr_uint_t)ins_ref->pc);
    fprintf(data->logf, PIFX",", (ptr_uint_t)ins_ref->pc);
    fprintf(data->logf, "0x%02x,\"", (ptr_uint_t)ins_ref->length);
    for(int i = 0; i < ins_ref->length; i++) {
        fprintf(data->logf, "\\x%02x", *(byte *)(ins_ref->pc+i));
    }
    fprintf(data->logf, "\")\n");
    data->num_refs++;

    BUF_PTR(data->seg_base) = data->buf_base;
}

static void
covset(void *drcontext) 
{
    // dr_printf("%d\n", __LINE__);
    per_thread_t *data;
    ins_ref_t *ins_ref, *buf_ptr;
    // dr_printf("%d\n", __LINE__);
    data    = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    // dr_printf("%d\n", __LINE__);
    buf_ptr = BUF_PTR(data->seg_base);
    // dr_printf("%d\n", __LINE__);

    for (ins_ref = (ins_ref_t *)data->buf_base; ins_ref < (buf_ptr-1); ins_ref++) {
        /* We use PIFX to avoid leading zeroes and shrink the resulting file. */
        data->num_refs++;
    }

    ptr_uint_t curr_loc = (ptr_uint_t)ins_ref->pc;
    // dr_printf("%d\n", __LINE__);
    curr_loc = (curr_loc >> 4) ^ (curr_loc << 8);
    // dr_printf("%d\n", __LINE__);
    ptr_uint_t edge_id = curr_loc ^ data->prev_loc;
    // dr_printf("%d\n", __LINE__);
    data->prev_loc = (curr_loc >> 1);

    // dr_printf("%d\n", __LINE__);
    // edge_count[edge_id]++;
    // dr_printf("%d\n", __LINE__);
    // bb_count[curr_loc]++;

    edge_set.insert(edge_id);
    // fwrite(&edge_id, sizeof(byte), sizeof(edge_id), data->logf);

    // dr_printf("%d\n", __LINE__);
    data->num_refs++;

    // dr_printf("%d\n", __LINE__);
    BUF_PTR(data->seg_base) = data->buf_base;
    // dr_printf("%d\n", __LINE__);
}

/* clean_call dumps the memory reference info to the log file */
static void
clean_call(void)
{
    void *drcontext = dr_get_current_drcontext();
    instrace(drcontext);
}

static void
clean_call_bb(void)
{
    // dr_printf("%d\n", __LINE__);
    void *drcontext = dr_get_current_drcontext();
    // dr_printf("%d\n", __LINE__);
    covset(drcontext);
    // dr_printf("%d\n", __LINE__);
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

/* insert inline code to add an instruction entry into the buffer */
static void
instrument_instr(void *drcontext, instrlist_t *ilist, instr_t *where)
{
    /* We need two scratch registers */
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

    /* Restore scratch registers */
    if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS)
        DR_ASSERT(false);
}

/* For each app instr, we insert inline code to fill the buffer. */
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
    /* we don't want to auto-predicate any instrumentation */
    // drmgr_disable_auto_predication(drcontext, bb);

    if (!instr_is_app(instr))
        return DR_EMIT_DEFAULT;

    /* insert code to add an entry to the buffer */
    instrument_instr(drcontext, bb, instr);

    /* insert code once per bb to call clean_call for processing the buffer */
    if (drmgr_is_first_instr(drcontext, instr)
        /* XXX i#1698: there are constraints for code between ldrex/strex pairs,
         * so we minimize the instrumentation in between by skipping the clean call.
         * We're relying a bit on the typical code sequence with either ldrex..strex
         * in the same bb, in which case our call at the start of the bb is fine,
         * or with a branch in between and the strex at the start of the next bb.
         * However, there is still a chance that the instrumentation code may clear the
         * exclusive monitor state.
         * Using a fault to handle a full buffer should be more robust, and the
         * forthcoming buffer filling API (i#513) will provide that.
         */
        IF_AARCHXX(&& !instr_is_exclusive_store(instr)))
        dr_insert_clean_call(drcontext, bb, instr, (void *)clean_call, false, 0);

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
    // dr_printf("%d\n", __LINE__);
    if (!instr_is_app(instr))
        return DR_EMIT_DEFAULT;

    // dr_printf("%d\n", __LINE__);
    instrument_instr(drcontext, bb, instr);
    if (drmgr_is_first_instr(drcontext, instr) IF_AARCHXX(&& !instr_is_exclusive_store(instr))) {
        // dr_printf("%d\n", __LINE__);
        // dr_printf("%d\n", __LINE__);
        dr_insert_clean_call(drcontext, bb, instr, (void *)clean_call_bb, false, 0);
    }
    // dr_printf("%d\n", __LINE__);

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

    /* We're going to dump our data to a per-thread file.
     * On Windows we need an absolute path so we place it in
     * the same directory as our library. We could also pass
     * in a path as a client argument.
     */
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

    // fprintf(data->logf, "edges = {}\n");
    // fprintf(data->logf, "def EDGE(edge_id):\n");
    // fprintf(data->logf, "    if edge_id not in edges:\n");
    // fprintf(data->logf, "        edges[edge_id] = 0\n");
    // fprintf(data->logf, "    edges[edge_id] += 1\n");
    // fprintf(data->logf, "\n");
    // fprintf(data->logf, "def INS(addr, len, bytes):\n");
    // fprintf(data->logf, "    return\n");
    // fprintf(data->logf, "\n");
    // fprintf(data->logf, "bbs = {}\n");
    // fprintf(data->logf, "def BB(addr):\n");
    // fprintf(data->logf, "    if addr not in bbs:\n");
    // fprintf(data->logf, "        bbs[addr] = 0\n");
    // fprintf(data->logf, "    bbs[addr] += 1\n");
    // fprintf(data->logf, "\n");
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

// std::map<ptr_uint_t, uint64> edge_count;
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
event_exit(void)
{
    dr_log(NULL, LOG_ALL, 1, "Client 'instrace' num refs seen: %lld\n", num_refs);
    if (!dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT))
        DR_ASSERT(false);

    if (!drmgr_unregister_tls_field(tls_idx) ||
        !drmgr_unregister_thread_init_event(event_thread_init) ||
        !drmgr_unregister_thread_exit_event(EVENT_THREAD_EXIT) ||
        !drmgr_unregister_bb_insertion_event(EVENT_APP) ||
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
        per_thread_t *data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
        // fprintf(data->logf, "crashed 0x%x 0x%llx\n", exception_code, excpt->record->ExceptionAddress);
        dr_exit_process(1);
    }
    return true;
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    /* We need 2 reg slots beyond drreg's eflags slots => 3 slots */
    // dr_printf("%d\n", __LINE__);
    drreg_options_t ops = {sizeof(ops), 3, false};
    dr_set_client_name("DynamoRIO Sample Client 'instrace'",
                       "http://dynamorio.org/issues");
    if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS)
        DR_ASSERT(false);

    /* register events */
    dr_register_exit_event(event_exit);
    // dr_printf("%d\n", __LINE__);
    if (!drmgr_register_thread_init_event(event_thread_init) ||
        !drmgr_register_thread_exit_event(EVENT_THREAD_EXIT) ||
        !drmgr_register_bb_instrumentation_event(NULL /*analysis_func*/,
                                                 EVENT_APP,
                                                 NULL) ||
        !drmgr_register_exception_event(onexception)) 
    {
        DR_ASSERT(false);
    }
    // dr_printf("%d\n", __LINE__);

    client_id = id;
    mutex = dr_mutex_create();

    tls_idx = drmgr_register_tls_field();
    DR_ASSERT(tls_idx != -1);
    /* The TLS field provided by DR cannot be directly accessed from the code cache.
     * For better performance, we allocate raw TLS so that we can directly
     * access and update it with a single instruction.
     */
    if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, INSTRACE_TLS_COUNT, 0))
        DR_ASSERT(false);

    dr_log(NULL, LOG_ALL, 1, "Client 'instrace' initializing\n");
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
