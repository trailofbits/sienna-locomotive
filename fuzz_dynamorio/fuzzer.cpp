#include <map>
#include <array>

#include "common/sl2_dr_client.hpp"
#include "common/sl2_dr_client_options.hpp"
#include "vendor/picosha2.h"
#include "common/mutation.hpp"
#include "common/sl2_server_api.hpp"

// NOTE(ww): 1024 seems like a reasonable default here -- most programs won't have
// more than 1024 modules, and those that do will probably have loaded the ones
// we want to do coverage for anyways.
#define SL2_MAX_MODULES 1024

static droption_t<bool> op_no_coverage(
    DROPTION_SCOPE_CLIENT,
    "n",
    false,
    "nocoverage",
    "disable coverage, even when possible");

static droption_t<std::string> op_run_id(
    DROPTION_SCOPE_CLIENT,
    "r",
    "",
    "run_id",
    "specify the run ID for this fuzzer instance");

static droption_t<std::string> op_arena_id(
    DROPTION_SCOPE_CLIENT,
    "a",
    "",
    "arena_id",
    "specify the arena ID for coverage guidance");


// TODO(ww): Add options here for edge/bb coverage,
// if we decided to support edge as well.

// TODO(ww): These should all go in one class/struct, probably a "Fuzzer" subclass
// of SL2Client.
static SL2Client client;
static sl2_conn sl2_conn;
static sl2_exception_ctx fuzz_exception_ctx;
static bool crashed = false;
static uint32_t mut_count = 0;
static sl2_arena arena = {0};
static bool coverage_guided = false;
static std::array<module_data_t *, SL2_MAX_MODULES> seen_modules;
static uint32_t nmodules = 0;
// TODO(ww): Benchmark std::set vs std::vector -- how badly is nonlocality of access in sets
// going to hurt us here?
// static std::set<module_data_t *, std::less<module_data_t *>, sl2_dr_allocator<module_data_t *>> seen_modules;
static module_data_t *target_mod;

static bool
is_blacklisted_coverage_module(app_pc addr)
{
    module_data_t *containing_module = NULL;

    for (uint32_t i = 0; i < nmodules; ++i) {
        if (dr_module_contains_addr(seen_modules[i], addr)) {
            containing_module = seen_modules[i];
            break;
        }
    }

    // NOTE(ww): This should (almsot) never happen, since every executable address
    // should belong to *some* module and the vast majority of programs will have
    // fewer than SL2_MAX_MODULES. If it does happen, assume the
    // worst (that it's blacklisted).
    if (!containing_module) {
        SL2_DR_DEBUG("addr=%lu doesn't have a (covered) module?!\n");
        return true;
    }

    // TODO(ww): We could probably inline this call manually.
    return !strncmp("C:\\Windows\\", containing_module->full_path, 11);
}

static dr_emit_flags_t
on_bb_instrument(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst, bool for_trace, bool translating, void *user_data)
{
    app_pc start_pc;
    uint16_t offset;

    if (!drmgr_is_first_instr(drcontext, inst)) {
        return DR_EMIT_DEFAULT;
    }

    start_pc = dr_fragment_app_pc(tag);

    if (is_blacklisted_coverage_module(start_pc)) {
        return DR_EMIT_DEFAULT;
    }

    offset = (start_pc - target_mod->start) & (FUZZ_ARENA_SIZE - 1);

    drreg_reserve_aflags(drcontext, bb, inst);
    // TODO(ww): Is it really necessary to inject an instruction here?
    // This is how WinAFL does it, but we don't use shared memory like they do.
    instrlist_meta_preinsert(bb, inst, INSTR_CREATE_inc(drcontext,
        OPND_CREATE_ABSMEM(&(arena.map[offset]), OPSZ_1)));
    drreg_unreserve_aflags(drcontext, bb, inst);

    return DR_EMIT_DEFAULT;
}

/* Maps exception code to an exit status. Print it out, then exit. */
static bool
on_exception(void *drcontext, dr_exception_t *excpt)
{
    dr_log(NULL, DR_LOG_ALL, ERROR, "fuzzer#on_exception: Exception occurred!\n");
    crashed = true;
    DWORD exception_code = excpt->record->ExceptionCode;

    dr_switch_to_app_state(drcontext);
    fuzz_exception_ctx.thread_id = GetCurrentThreadId();
    dr_mcontext_to_context(&(fuzz_exception_ctx.thread_ctx), excpt->mcontext);
    dr_switch_to_dr_state(drcontext);

    // Make our own copy of the exception record.
    memcpy(&(fuzz_exception_ctx.record), excpt->record, sizeof(EXCEPTION_RECORD));

    json j;
    j["exception"] = client.exception_to_string(exception_code);
    SL2_LOG_JSONL(j);

    dr_exit_process(1);
    return true;
}

/* Runs after the target application has exited */
static void
on_dr_exit(void)
{
    SL2_DR_DEBUG("Dynamorio exiting (fuzzer)\n");

    if (crashed) {
        char run_id_s[SL2_UUID_SIZE];
        sl2_uuid_to_string(sl2_conn.run_id, run_id_s);
        SL2_DR_DEBUG("<crash found for run id %s>\n", run_id_s);
        dr_log(NULL, DR_LOG_ALL, ERROR, "fuzzer#on_dr_exit: Crash found for run id %s!", run_id_s);

        sl2_crash_paths crash_paths = {0};
        sl2_conn_request_crash_paths(&sl2_conn, dr_get_process_id(), &crash_paths);

        // NOTE(ww): `dr_open_file` et al. don't work here, presumably because we explicitly
        // switch to the target app state to perform the actual minidump write.
        HANDLE dump_file = CreateFile(crash_paths.initial_dump_path,
            GENERIC_WRITE,
            NULL, NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (dump_file == INVALID_HANDLE_VALUE) {
            SL2_DR_DEBUG("fuzzer#on_dr_exit: could not open the initial dump file (0x%x)\n", GetLastError());
        }

        EXCEPTION_POINTERS exception_pointers = {0};
        MINIDUMP_EXCEPTION_INFORMATION mdump_info = {0};

        exception_pointers.ExceptionRecord = &(fuzz_exception_ctx.record);
        exception_pointers.ContextRecord = &(fuzz_exception_ctx.thread_ctx);

        mdump_info.ThreadId = fuzz_exception_ctx.thread_id;
        mdump_info.ExceptionPointers = &exception_pointers;
        mdump_info.ClientPointers = true;

        // NOTE(ww): Switching back to the application's state is necessary, as we don't want
        // parts of the instrumentation showing up in our initial dump.
        dr_switch_to_app_state(dr_get_current_drcontext());

        MiniDumpWriteDump(
            GetCurrentProcess(),
            GetCurrentProcessId(),
            dump_file,
            MiniDumpNormal,
            &mdump_info,
            NULL, NULL);

        dr_switch_to_dr_state(dr_get_current_drcontext());

        CloseHandle(dump_file);
    }


    if (coverage_guided) {
        sl2_conn_register_arena(&sl2_conn, &arena);
    }

    sl2_conn_close(&sl2_conn);

    dr_free_module_data(target_mod);

    for (uint32_t i = 0; i < nmodules; ++i) {
        dr_free_module_data(seen_modules[i]);
    }

    // Clean up DynamoRIO
    // TODO(ww): Clean up individual event handlers as well? Since we're about to exit,
    // do we really need to? The wizard and tracer do (for the most part).
    dr_log(NULL, DR_LOG_ALL, ERROR, "fuzzer#on_dr_exit: Dynamorio Exiting\n");
    drwrap_exit();
    drmgr_exit();
    drreg_exit();
}

// Mutates a function's input buffer, registers the mutation with the server, and writes the
// buffer into memory for fuzzing.
static bool
mutate(Function function, HANDLE hFile, size_t position, void *buffer, size_t bufsize)
{
    wchar_t resource[MAX_PATH + 1] = {0};

    // Check that ReadFile calls are to something actually valid
    // TODO(ww): Add fread and fread_s here once the _getosfhandle problem is fixed.
    if (function == Function::ReadFile) {
        if (hFile == INVALID_HANDLE_VALUE) {
            dr_log(NULL, DR_LOG_ALL, ERROR, "fuzzer#mutate: Invalid source for mutation?\n");
            return false;
        }

        GetFinalPathNameByHandle(hFile, resource, MAX_PATH, 0);
        SL2_DR_DEBUG("mutate: resource: %S\n", resource);
    }

    sl2_mutation mutation = {
        (uint32_t) function,
        mut_count++,
        0, // NOTE(ww): We don't know the mutation type yet.
        resource,
        position,
        bufsize,
        (uint8_t *) buffer,
    };

    if (coverage_guided) {
        sl2_mutation_advice advice;
        sl2_conn_advise_mutation(&sl2_conn, &arena, &advice);
        do_mutation_custom(&mutation, advice.strategy);
    }
    else {
        do_mutation(&mutation);
    }

    // SL2_DR_DEBUG("mutate: %.*s\n", mutation.bufsize, mutation.buffer);

    // Tell the server about our mutation.
    if (sl2_conn_register_mutation(&sl2_conn, &mutation) != SL2Response::OK) {
        SL2_DR_DEBUG("mutate: got an error response from the server!\n");
        return false;
    }

    return true;
}

static void wrap_pre_IsProcessorFeaturePresent(void *wrapcxt, OUT void **user_data)
{
    client.wrap_pre_IsProcessorFeaturePresent(wrapcxt, user_data);
}

static void wrap_post_IsProcessorFeaturePresent(void *wrapcxt, void *user_data)
{
    client.wrap_post_IsProcessorFeaturePresent(wrapcxt, user_data);
}

static void wrap_pre_UnhandledExceptionFilter(void *wrapcxt, OUT void **user_data)
{
    client.wrap_pre_UnhandledExceptionFilter(wrapcxt, user_data, on_exception);
}

static void wrap_pre_VerifierStopMessage(void *wrapcxt, OUT void **user_data)
{
    client.wrap_pre_VerifierStopMessage(wrapcxt, user_data, on_exception);
}

static void
wrap_pre_ReadEventLog(void *wrapcxt, OUT void **user_data)
{
    client.wrap_pre_ReadEventLog(wrapcxt, user_data);
}

static void
wrap_pre_RegQueryValueEx(void *wrapcxt, OUT void **user_data)
{
    client.wrap_pre_RegQueryValueEx(wrapcxt, user_data);
}

static void
wrap_pre_WinHttpWebSocketReceive(void *wrapcxt, OUT void **user_data)
{
    client.wrap_pre_WinHttpWebSocketReceive(wrapcxt, user_data);
}

static void
wrap_pre_InternetReadFile(void *wrapcxt, OUT void **user_data)
{
    client.wrap_pre_InternetReadFile(wrapcxt, user_data);
}

static void
wrap_pre_WinHttpReadData(void *wrapcxt, OUT void **user_data)
{
    client.wrap_pre_WinHttpReadData(wrapcxt, user_data);
}

static void
wrap_pre_recv(void *wrapcxt, OUT void **user_data)
{
    client.wrap_pre_recv(wrapcxt, user_data);
}

static void
wrap_pre_ReadFile(void *wrapcxt, OUT void **user_data)
{
    client.wrap_pre_ReadFile(wrapcxt, user_data);
}

static void
wrap_pre_fread_s(void *wrapcxt, OUT void **user_data)
{
    client.wrap_pre_fread_s(wrapcxt, user_data);
}

static void
wrap_pre_fread(void *wrapcxt, OUT void **user_data)
{
    client.wrap_pre_fread(wrapcxt, user_data);
}

static void
wrap_pre__read(void *wrapcxt, OUT void **user_data)
{
    client.wrap_pre__read(wrapcxt, user_data);
}

static void
wrap_pre_MapViewOfFile(void *wrapcxt, OUT void **user_data)
{
    client.wrap_pre_MapViewOfFile(wrapcxt, user_data);
}

/* Mutates whatever data the hooked function wrote */
static void
wrap_post_Generic(void *wrapcxt, void *user_data)
{
    void *drcontext = NULL;

    if (!client.is_sane_post_hook(wrapcxt, user_data, &drcontext)) {
        return;
    }

    SL2_DR_DEBUG("<in wrap_post_Generic>\n");

    client_read_info *info = (client_read_info *) user_data;

    // Identify whether this is the function we want to target
    bool targeted = client.is_function_targeted(info);
    client.incrementCallCountForFunction(info->function);

    // NOTE(ww): We should never read more bytes than we request, so this is more
    // of a sanity check than anything else.
    if (info->lpNumberOfBytesRead && *(info->lpNumberOfBytesRead) < info->nNumberOfBytesToRead) {
        info->nNumberOfBytesToRead = *(info->lpNumberOfBytesRead);
    }

    if (targeted) {
        // If the mutation process fails in any way, consider this fuzzing run a loss.
        if (!mutate(info->function, info->hFile, info->position, info->lpBuffer, info->nNumberOfBytesToRead)) {
            crashed = false;
            dr_exit_process(1);
        }
    }

    if (info->argHash) {
        dr_thread_free(drcontext, info->argHash, SL2_HASH_LEN + 1);
    }

    dr_thread_free(drcontext, info, sizeof(client_read_info));
}

// NOTE(ww): MapViewOfFile can't use the Generic post-hook, as
// we need the address of the mapped view that it returns.
static void
wrap_post_MapViewOfFile(void *wrapcxt, void *user_data)
{
    void *drcontext = NULL;

    if (!client.is_sane_post_hook(wrapcxt, user_data, &drcontext)) {
        return;
    }

    SL2_DR_DEBUG("<in wrap_post_MapViewOfFile>\n");

    client_read_info *info = (client_read_info *) user_data;
    info->lpBuffer = drwrap_get_retval(wrapcxt);
    MEMORY_BASIC_INFORMATION memory_info = {0};

    if (!info->nNumberOfBytesToRead) {
        dr_virtual_query((byte *) info->lpBuffer, &memory_info, sizeof(memory_info));

        info->nNumberOfBytesToRead = memory_info.RegionSize;
    }

    fileArgHash fStruct = {0};
    fStruct.readSize = info->nNumberOfBytesToRead;

    // NOTE(ww): The wizard should weed these failures out for us; if it happens
    // here, there's not much we can do.
    if (!GetMappedFileName(GetCurrentProcess(), info->lpBuffer, fStruct.fileName, MAX_PATH)) {
        SL2_DR_DEBUG("Fatal: Couldn't get filename for memory map! Aborting.\n");
        crashed = false;
        dr_exit_process(1);
    }

    // Create the argHash, now that we have the correct source and nNumberOfBytesToRead.
    client.hash_args(info->argHash, &fStruct);

    bool targeted = client.is_function_targeted(info);
    client.incrementCallCountForFunction(info->function);

    if (targeted) {
        // If the mutation process fails in any way, consider this fuzzing run a loss.
        if (!mutate(info->function, info->hFile, info->position, info->lpBuffer, info->nNumberOfBytesToRead)) {
            crashed = false;
            dr_exit_process(1);
        }
    }

    dr_thread_free(drcontext, info->argHash, SL2_HASH_LEN + 1);
    dr_thread_free(drcontext, info, sizeof(client_read_info));
}

/* Runs when a new module (typically an exe or dll) is loaded. Tells DynamoRIO to hook all the interesting functions
    in that module. */
static void
on_module_load(void *drcontext, const module_data_t *mod, bool loaded)
{
    if (nmodules < SL2_MAX_MODULES - 1) {
        // Add a copy of the module to our seen module map so that we can avoid
        // doing basic block coverage of it later (if necessary).
        seen_modules[nmodules++] = dr_copy_module_data(mod);
    }
    else {
        SL2_DR_DEBUG("fuzzer#on_module_load: Only doing coverage on the first %d.\n", SL2_MAX_MODULES);
    }

    if (!strcmp(dr_get_application_name(), dr_module_preferred_name(mod))) {
        client.baseAddr = (uint64_t) mod->start;
    }

    const char *mod_name = dr_module_preferred_name(mod);
    app_pc towrap;

    sl2_pre_proto_map pre_hooks;
    SL2_PRE_HOOK1(pre_hooks, ReadFile);
    SL2_PRE_HOOK1(pre_hooks, InternetReadFile);
    SL2_PRE_HOOK2(pre_hooks, ReadEventLogA, ReadEventLog);
    SL2_PRE_HOOK2(pre_hooks, ReadEventLogW, ReadEventLog);

    if (op_registry.get_value()) {
        SL2_PRE_HOOK2(pre_hooks, RegQueryValueExW, RegQueryValueEx);
        SL2_PRE_HOOK2(pre_hooks, RegQueryValueExA, RegQueryValueEx);
    }

    SL2_PRE_HOOK1(pre_hooks, WinHttpWebSocketReceive);
    SL2_PRE_HOOK1(pre_hooks, WinHttpReadData);
    SL2_PRE_HOOK1(pre_hooks, recv);
    SL2_PRE_HOOK1(pre_hooks, fread_s);
    SL2_PRE_HOOK1(pre_hooks, fread);
    SL2_PRE_HOOK1(pre_hooks, _read);
    SL2_PRE_HOOK1(pre_hooks, MapViewOfFile);

    sl2_post_proto_map post_hooks;
    SL2_POST_HOOK2(post_hooks, ReadFile, Generic);
    SL2_POST_HOOK2(post_hooks, InternetReadFile, Generic);
    SL2_POST_HOOK2(post_hooks, ReadEventLogA, Generic);
    SL2_POST_HOOK2(post_hooks, ReadEventLogW, Generic);

    if (op_registry.get_value()) {
        SL2_POST_HOOK2(post_hooks, RegQueryValueExW, Generic);
        SL2_POST_HOOK2(post_hooks, RegQueryValueExA, Generic);
    }

    SL2_POST_HOOK2(post_hooks, WinHttpWebSocketReceive, Generic);
    SL2_POST_HOOK2(post_hooks, WinHttpReadData, Generic);
    SL2_POST_HOOK2(post_hooks, recv, Generic);
    SL2_POST_HOOK2(post_hooks, fread_s, Generic);
    SL2_POST_HOOK2(post_hooks, fread, Generic);
    SL2_POST_HOOK2(post_hooks, _read, Generic);
    SL2_POST_HOOK1(post_hooks, MapViewOfFile);

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
    if (STREQ(mod_name, "VERIFIER.DLL")) {
        SL2_DR_DEBUG("loading Application Verifier mitigations\n");

        towrap = (app_pc) dr_get_proc_address(mod->handle, "VerifierStopMessage");
        drwrap_wrap(towrap, wrap_pre_VerifierStopMessage, NULL);

        towrap = (app_pc) dr_get_proc_address(mod->handle, "VerifierStopMessageEx");
        drwrap_wrap(towrap, wrap_pre_VerifierStopMessage, NULL);
    }

    // TODO(ww): Wrap DllDebugObjectRpcHook.
    if (STREQ(mod_name, "OLE32.DLL")) {
        SL2_DR_DEBUG("OLE32.DLL loaded, but we don't have an DllDebugObjectRpcHook mitigation yet!\n");
    }

    void(__cdecl *pre_hook)(void *, void **);
    void(__cdecl *post_hook)(void *, void *);

    sl2_pre_proto_map::iterator it;
    for(it = pre_hooks.begin(); it != pre_hooks.end(); it++) {
        char *function_name = it->first;
        bool hook = false;

        if (!client.function_is_in_expected_module(function_name, mod_name)) {
            continue;
        }

        for (targetFunction t : client.parsedJson) {
            if (t.selected && STREQ(t.functionName.c_str(), function_name)){
                hook = true;
            }
            else if (t.selected && (STREQ(function_name, "RegQueryValueExW") || STREQ(function_name, "RegQueryValueExA"))) {
                if (!STREQ(t.functionName.c_str(), "RegQueryValueEx")) {
                    hook = false;
                }
            }
        }

        if (!hook) {
            continue;
        }

        pre_hook = it->second;
        post_hook = post_hooks[function_name];

        // Only hook ReadFile calls from the kernel (TODO - investigate fuzzgoat results)
        towrap = (app_pc) dr_get_proc_address(mod->handle, function_name);

        // If everything looks good and we've made it this far, wrap the function
        if (towrap != NULL) {
            dr_flush_region(towrap, 0x1000);
            bool ok = drwrap_wrap(towrap, pre_hook, post_hook);
            if (ok) {
                SL2_DR_DEBUG("<wrapped %s @ 0x%p in %s\n", function_name, towrap, mod_name);
            } else {
                SL2_DR_DEBUG("<FAILED to wrap %s @ 0x%p: already wrapped?\n", function_name, towrap);
            }
        }
    }
}


/* Runs after process initialization. Initializes DynamoRIO */
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("Sienna-Locomotive Fuzzer",
                       "https://github.com/trailofbits/sienna-locomotive/issues");

    // Parse command line options
    std::string parse_err;
    int last_idx = 0;
    if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, &parse_err, &last_idx)) {
        SL2_DR_DEBUG("Usage error: %s", parse_err.c_str());
        dr_abort();
    }

    std::string target = op_target.get_value();

    if (target == "") {
        SL2_DR_DEBUG("ERROR: arg -t (target file) required\n");
        dr_abort();
    }

    bool no_coverage = op_no_coverage.get_value();

    std::string run_id_s = op_run_id.get_value();
    std::string arena_id_s = op_arena_id.get_value();

    if (run_id_s == "") {
        SL2_DR_DEBUG("ERROR: arg -r required\n");
        dr_abort();
    }

    if (!client.loadJson(target)) {
        SL2_DR_DEBUG("Failed to load targets!\n");
        dr_abort();
    }

    dr_enable_console_printing();
    // Set up console printing
    dr_log(NULL, DR_LOG_ALL, 1, "DR client 'SL Fuzzer' initializing\n");
    if (dr_is_notify_on()) {
        dr_log(NULL, DR_LOG_ALL, ERROR, "Client SL Fuzzer is running\n");
    }

    if (sl2_conn_open(&sl2_conn) != SL2Response::OK) {
        SL2_DR_DEBUG("ERROR: Couldn't open a connection to the server!\n");
        dr_abort();
    }

    UUID run_id;
    sl2_string_to_uuid(run_id_s.c_str(), &run_id);
    sl2_conn_assign_run_id(&sl2_conn, run_id);

    sl2_conn_register_pid(&sl2_conn, dr_get_process_id(), false);

    // TODO(ww): Guard these initializations.
    drmgr_init();
    drwrap_init();

    drreg_options_t opts = {sizeof(opts), 3, false};
    drreg_init(&opts);

    // Check whether we can use coverage on this fuzzing run
    coverage_guided = (arena_id_s != "") && !no_coverage;

    // Cache our main module, so that we don't have to retrieve it during each
    // basic block event.
    target_mod = dr_get_main_module();

    if (coverage_guided) {
        SL2_DR_DEBUG("dr_client_main: arena given, instrumenting BBs!\n");
        mbstowcs_s(NULL, arena.id, SL2_HASH_LEN + 1, arena_id_s.c_str(), SL2_HASH_LEN);
        sl2_conn_request_arena(&sl2_conn, &arena);
        drmgr_register_bb_instrumentation_event(NULL, on_bb_instrument, NULL);
    }
    else {
        SL2_DR_DEBUG("dr_client_main: no arena given OR user requested dumb fuzzing!\n");
    }

    drmgr_register_exception_event(on_exception);
    dr_register_exit_event(on_dr_exit);
    drmgr_register_module_load_event(on_module_load);
}
