#include <map>
#include <stdio.h>
#include <fstream>

#include <winsock2.h>
#include <winhttp.h>
#include <Windows.h>
#include <Winternl.h>
#include <Rpc.h>
#include <io.h>
#include <Dbghelp.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"
#include "droption.h"
#include "drreg.h"

#include "vendor/picosha2.h"

#include "common/mutation.hpp"
#include "common/sl2_server_api.hpp"
#include "common/sl2_dr_client.hpp"
#include "common/sl2_dr_client_options.hpp"

// Metadata object for a target function call
struct fuzzer_read_info {
    Function function;
    HANDLE hFile;
    void *lpBuffer;
    size_t nNumberOfBytesToRead;
    DWORD *lpNumberOfBytesRead;
    uint64_t position;
    uint64_t retAddrOffset;
    // TODO(ww): Make this a wchar_t * for consistency.
    char *argHash;
};

static bool mutate(HANDLE hFile, size_t position, void *buf, size_t size);

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


// TODO(ww): Add options here for edge/bb coverage,
// if we decided to support edge as well.

// TODO(ww): These should all go in one class/struct, probably a "Fuzzer" subclass
// of SL2Client.
static SL2Client client;
static sl2_conn sl2_conn;
static sl2_exception_ctx fuzz_exception_ctx;
static bool crashed = false;
static uint64_t baseAddr;
static uint32_t mut_count = 0;
static sl2_arena arena = {0};
static bool coverage_guided = false;
static module_data_t *target_mod;

static dr_emit_flags_t
on_bb_instrument(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst, bool for_trace, bool translating, void *user_data)
{
    app_pc start_pc;
    uint16_t offset;

    if (!drmgr_is_first_instr(drcontext, inst)) {
        return DR_EMIT_DEFAULT;
    }

    start_pc = dr_fragment_app_pc(tag);
    // NOTE(ww): This suffices for a fuzzing target that's a single executable.
    // For more complex targets, will we need to allow the user to supply a list of modules to
    // instrument.
    if (!dr_module_contains_addr(target_mod, start_pc)) {
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
    j["exception"] = exception_to_string(exception_code);
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
        sl2_conn_request_crash_paths(&sl2_conn, &crash_paths);

        HANDLE hDumpFile = CreateFile(crash_paths.initial_dump_path,
            GENERIC_WRITE,
            NULL, NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (hDumpFile == INVALID_HANDLE_VALUE) {
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
            hDumpFile,
            MiniDumpNormal,
            &mdump_info,
            NULL, NULL);

        dr_switch_to_dr_state(dr_get_current_drcontext());

        CloseHandle(hDumpFile);
    }

    if (coverage_guided) {
        sl2_conn_register_arena(&sl2_conn, &arena);
    }

    sl2_conn_close(&sl2_conn);

    dr_free_module_data(target_mod);

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
        // sl2_mutation_advice advice;
        // sl2_conn_advise_mutation(&sl2_conn, &arena, &advice);
        // mutate_buffer_arena(mutation.buffer, mutation.bufsize, &advice);
        do_mutation(&mutation);
    }
    else {
        do_mutation(&mutation);
    }

    SL2_DR_DEBUG("mutate: %.*s\n", mutation.bufsize, mutation.buffer);

    // Tell the server about our mutation.
    sl2_conn_register_mutation(&sl2_conn, &mutation);

    return true;
}

/*
    The next three functions are used to intercept __fastfail, which Windows
    provides to allow processes to request immediate termination.

    To get around this, we tell the target that __fastfail isn't avaiable.
    We then hope that they craft an exception record instead and send it
    to UnhandledException, where we intercept it and forward it to our
    exception handler. If the target decides to do neither of these, we
    still miss the exception.

    This trick was cribbed from WinAFL:
    https://github.com/ivanfratric/winafl/blob/73c7b41/winafl.c#L600

    NOTE(ww): These functions are duplicated across the fuzzer and the tracer.
    Keep them synced!
*/

static void wrap_pre_IsProcessorFeaturePresent(void *wrapcxt, OUT void **user_data)
{
    #pragma warning(suppress: 4311 4302)
    DWORD feature = (DWORD) drwrap_get_arg(wrapcxt, 0);

    #pragma warning(suppress: 4312)
    *user_data = (void *) feature;
}

static void wrap_post_IsProcessorFeaturePresent(void *wrapcxt, void *user_data)
{
    #pragma warning(suppress: 4311 4302)
    DWORD feature = (DWORD) user_data;

    if (feature == PF_FASTFAIL_AVAILABLE) {
        SL2_DR_DEBUG("wrap_post_IsProcessorFeaturePresent: got PF_FASTFAIL_AVAILABLE request, masking\n");
        drwrap_set_retval(wrapcxt, (void *) 0);
    }
}

static void wrap_pre_UnhandledExceptionFilter(void *wrapcxt, OUT void **user_data)
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
  The next several functions are wrappers that DynamoRIO calls before each of the targeted functions runs. Each of them
  records metadata about the target function call for use later.
*/

/*
    bool ReadEventLog(
      _In_  HANDLE hEventLog,
      _In_  DWORD  dwReadFlags,
      _In_  DWORD  dwRecordOffset,
      _Out_ LPVOID lpBuffer,
      _In_  DWORD  nNumberOfBytesToRead,
      _Out_ DWORD  *pnBytesRead,
      _Out_ DWORD  *pnMinNumberOfBytesNeeded
    );

    Return: If the function succeeds, the return value is nonzero.
*/
static void
wrap_pre_ReadEventLog(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_ReadEventLog>\n");
    HANDLE hEventLog = (HANDLE)drwrap_get_arg(wrapcxt, 0);
    #pragma warning(suppress: 4311 4302)
    DWORD  dwReadFlags = (DWORD)drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    DWORD  dwRecordOffset = (DWORD)drwrap_get_arg(wrapcxt, 2);
    void *lpBuffer = (void *)drwrap_get_arg(wrapcxt, 3);
    #pragma warning(suppress: 4311 4302)
    DWORD  nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 4);
    DWORD  *pnBytesRead = (DWORD *)drwrap_get_arg(wrapcxt, 5);
    DWORD  *pnMinNumberOfBytesNeeded = (DWORD *)drwrap_get_arg(wrapcxt, 6);

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::ReadEventLog;
    info->hFile                = hEventLog;
    info->lpBuffer             = lpBuffer;
    info->nNumberOfBytesToRead = nNumberOfBytesToRead;
    info->lpNumberOfBytesRead  = pnBytesRead;
    info->position             = 0;
    info->retAddrOffset        = (uint64_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}


/*
    LONG WINAPI RegQueryValueEx(
      _In_        HKEY    hKey,
      _In_opt_    LPCTSTR lpValueName,
      _Reserved_  LPDWORD lpReserved,
      _Out_opt_   LPDWORD lpType,
      _Out_opt_   LPBYTE  lpData,
      _Inout_opt_ LPDWORD lpcbData
    );

    Return: If the function succeeds, the return value is ERROR_SUCCESS.
*/
static void
wrap_pre_RegQueryValueEx(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_RegQueryValueEx>\n");
    HKEY    hKey = (HKEY)drwrap_get_arg(wrapcxt, 0);
    LPCTSTR lpValueName = (LPCTSTR)drwrap_get_arg(wrapcxt, 1);
    LPDWORD lpReserved = (LPDWORD)drwrap_get_arg(wrapcxt, 2);
    LPDWORD lpType = (LPDWORD)drwrap_get_arg(wrapcxt, 3);
    LPBYTE  lpData = (LPBYTE)drwrap_get_arg(wrapcxt, 4);
    LPDWORD lpcbData = (LPDWORD)drwrap_get_arg(wrapcxt, 5);

    if (lpData != NULL && lpcbData != NULL) {
        *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
        client_read_info *info = (client_read_info *) *user_data;


        info->function             = Function::RegQueryValueEx;
        info->hFile                = hKey;
        info->lpBuffer             = lpData;
        info->nNumberOfBytesToRead = *lpcbData;
        info->lpNumberOfBytesRead  = lpcbData;
        info->position             = 0;
        info->retAddrOffset        = (uint64_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
        info->argHash              = NULL;
    } else {
        *user_data = NULL;
    }
}


/*
    DWORD WINAPI WinHttpWebSocketReceive(
      _In_  HINTERNET                      hWebSocket,
      _Out_ PVOID                          pvBuffer,
      _In_  DWORD                          dwBufferLength,
      _Out_ DWORD                          *pdwBytesRead,
      _Out_ WINHTTP_WEB_SOCKET_BUFFER_TYPE *peBufferType
    );

    Return: NO_ERROR on success. Otherwise an error code.
*/
static void
wrap_pre_WinHttpWebSocketReceive(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_WinHttpWebSocketReceive>\n");
    HINTERNET hRequest = (HINTERNET)drwrap_get_arg(wrapcxt, 0);
    PVOID pvBuffer = drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    DWORD dwBufferLength = (DWORD)drwrap_get_arg(wrapcxt, 2);
    PDWORD pdwBytesRead = (PDWORD)drwrap_get_arg(wrapcxt, 3);
    #pragma warning(suppress: 4311 4302)
    WINHTTP_WEB_SOCKET_BUFFER_TYPE peBufferType = (WINHTTP_WEB_SOCKET_BUFFER_TYPE)(int)drwrap_get_arg(wrapcxt, 3);

    // TODO: put this in another file cause you can't import wininet and winhttp
    // LONG positionHigh = 0;
    // DWORD positionLow = InternetSetFilePointer(hRequest, 0, &positionHigh, FILE_CURRENT);
    // uint64_t position = positionHigh;

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::WinHttpWebSocketReceive;
    info->hFile                = hRequest;
    info->lpBuffer             = pvBuffer;
    info->nNumberOfBytesToRead = dwBufferLength;
    info->lpNumberOfBytesRead  = pdwBytesRead;
    info->position             = 0;
    info->retAddrOffset        = (uint64_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}

/*
    bool InternetReadFile(
      _In_  HINTERNET hFile,
      _Out_ LPVOID    lpBuffer,
      _In_  DWORD     dwNumberOfBytesToRead,
      _Out_ LPDWORD   lpdwNumberOfBytesRead
    );

    Return: Returns TRUE if successful
*/
static void
wrap_pre_InternetReadFile(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_InternetReadFile>\n");
    HINTERNET hFile = (HINTERNET)drwrap_get_arg(wrapcxt, 0);
    void *lpBuffer = drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    DWORD nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 2);
    LPDWORD lpNumberOfBytesRead = (LPDWORD)drwrap_get_arg(wrapcxt, 3);

    // LONG positionHigh = 0;
    // DWORD positionLow = InternetSetFilePointer(hFile, 0, &positionHigh, FILE_CURRENT);
    // uint64_t position = positionHigh;

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::InternetReadFile;
    info->hFile                = hFile;
    info->lpBuffer             = lpBuffer;
    info->nNumberOfBytesToRead = nNumberOfBytesToRead;
    info->lpNumberOfBytesRead  = lpNumberOfBytesRead;
    info->position             = 0;
    info->retAddrOffset        = (uint64_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}

/*
    bool WINAPI WinHttpReadData(
      _In_  HINTERNET hRequest,
      _Out_ LPVOID    lpBuffer,
      _In_  DWORD     dwNumberOfBytesToRead,
      _Out_ LPDWORD   lpdwNumberOfBytesRead
    );

    Return: Returns TRUE if successful
*/
static void
wrap_pre_WinHttpReadData(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_WinHttpReadData>\n");
    HINTERNET hRequest = (HINTERNET)drwrap_get_arg(wrapcxt, 0);
    void *lpBuffer = drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    DWORD nNumberOfBytesToRead = (DWORD) drwrap_get_arg(wrapcxt, 2);
    DWORD *lpNumberOfBytesRead = (DWORD *) drwrap_get_arg(wrapcxt, 3);

    // LONG positionHigh = 0;
    // DWORD positionLow = InternetSetFilePointer(hRequest, 0, &positionHigh, FILE_CURRENT);
    // uint64_t position = positionHigh;

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::WinHttpReadData;
    info->hFile                = hRequest;
    info->lpBuffer             = lpBuffer;
    info->nNumberOfBytesToRead = nNumberOfBytesToRead;
    info->lpNumberOfBytesRead  = lpNumberOfBytesRead;
    info->position             = 0;
    info->retAddrOffset        = (uint64_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}


/*
    int recv(
      _In_  SOCKET s,
      _Out_ char   *buf,
      _In_  int    len,
      _In_  int    flags
    );

    Return: recv returns the number of bytes received
*/
static void
wrap_pre_recv(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_recv>\n");
    SOCKET s  = (SOCKET)drwrap_get_arg(wrapcxt, 0);
    char *buf = (char *)drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    int len   = (int)drwrap_get_arg(wrapcxt, 2);
    #pragma warning(suppress: 4311 4302)
    int flags = (int)drwrap_get_arg(wrapcxt, 3);

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::recv;
    info->hFile                = NULL;
    info->lpBuffer             = buf;
    info->nNumberOfBytesToRead = len;
    info->lpNumberOfBytesRead  = NULL;
    info->position             = 0;
    info->retAddrOffset        = (uint64_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}

/*
    bool WINAPI ReadFile(
      _In_        HANDLE       hFile,
      _Out_       LPVOID       lpBuffer,
      _In_        DWORD        nNumberOfBytesToRead,
      _Out_opt_   LPDWORD      lpNumberOfBytesRead,
      _Inout_opt_ LPOVERLAPPED lpOverlapped
    );

    Return: If the function succeeds, the return value is nonzero (TRUE).
*/
static void
wrap_pre_ReadFile(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_ReadFile>\n");
    HANDLE hFile                = drwrap_get_arg(wrapcxt, 0);
    void *lpBuffer             = drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    DWORD nNumberOfBytesToRead  = (DWORD)drwrap_get_arg(wrapcxt, 2);
    DWORD *lpNumberOfBytesRead = (DWORD*)drwrap_get_arg(wrapcxt, 3);

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

    info->function             = Function::ReadFile;
    info->hFile                = hFile;
    info->lpBuffer             = lpBuffer;
    info->nNumberOfBytesToRead = nNumberOfBytesToRead;
    info->lpNumberOfBytesRead  = lpNumberOfBytesRead;
    info->position             = fStruct.position;
    info->retAddrOffset        = (uint64_t) drwrap_get_retaddr(wrapcxt) - baseAddr;

    info->argHash = (char *) dr_thread_alloc(drwrap_get_drcontext(wrapcxt), SL2_HASH_LEN + 1);
    info->argHash[SL2_HASH_LEN] = 0;
    memcpy(info->argHash, hash_str.c_str(), SL2_HASH_LEN);
}

static void
wrap_pre_fread_s(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_fread_s>\n");
    void *buffer = (void *)drwrap_get_arg(wrapcxt, 0);
    #pragma warning(suppress: 4311 4302)
    size_t size  = (size_t)drwrap_get_arg(wrapcxt, 2);
    #pragma warning(suppress: 4311 4302)
    size_t count = (size_t)drwrap_get_arg(wrapcxt, 3);
    FILE *file   = (FILE *)drwrap_get_arg(wrapcxt, 4);

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::fread_s;
    // TODO(ww): Figure out why _get_osfhandle breaks DR.
    // info->hFile             = (HANDLE) _get_osfhandle(_fileno(file));
    info->hFile                = NULL;
    info->lpBuffer             = buffer;
    info->nNumberOfBytesToRead = size * count;
    info->lpNumberOfBytesRead  = NULL;
    info->position             = NULL;
    info->argHash              = NULL;
}

static void
wrap_pre_fread(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_fread>\n");

    void *buffer = (void *)drwrap_get_arg(wrapcxt, 0);
    #pragma warning(suppress: 4311 4302)
    size_t size  = (size_t)drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    size_t count = (size_t)drwrap_get_arg(wrapcxt, 2);
    FILE *file   = (FILE *)drwrap_get_arg(wrapcxt, 3);

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::fread;
    // TODO(ww): Figure out why _get_osfhandle breaks DR.
    // info->hFile             = (HANDLE) _get_osfhandle(_fileno(file));
    info->hFile                = NULL;
    info->lpBuffer             = buffer;
    info->nNumberOfBytesToRead = size * count;
    info->lpNumberOfBytesRead  = NULL;
    info->position             = NULL;
    info->retAddrOffset        = (uint64_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}

static void
wrap_pre__read(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre__read>\n");

    #pragma warning(suppress: 4311 4302)
    int fd = (int) drwrap_get_arg(wrapcxt, 0);
    void *buffer = drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    unsigned int count = (unsigned int) drwrap_get_arg(wrapcxt, 2);

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::_read;
    // TODO(ww): Figure out why _get_osfhandle breaks DR.
    // info->hFile             = (HANDLE) _get_osfhandle(fd);
    info->hFile                = NULL;
    info->lpBuffer             = buffer;
    info->nNumberOfBytesToRead = count;
    info->lpNumberOfBytesRead  = NULL;
    info->position             = NULL;
    info->retAddrOffset        = (uint64_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}


/* Mutates whatever data the hooked function wrote */
static void
wrap_post_Generic(void *wrapcxt, void *user_data)
{
    void *drcontext;

    if (!user_data) {
        SL2_DR_DEBUG("Warning: user_data=NULL in wrap_post_Generic!\n");
        return;
    }

    if (!wrapcxt) {
        SL2_DR_DEBUG("Warning: wrapcxt=NULL in wrap_post_Generic! Using dr_get_current_drcontext.\n");
        drcontext = dr_get_current_drcontext();
    }
    else {
        drcontext = drwrap_get_drcontext(wrapcxt);
    }

    SL2_DR_DEBUG("<in wrap_post_Generic>\n");

    client_read_info *info = (client_read_info *) user_data;

    // Grab stored metadata
    size_t nNumberOfBytesToRead = info->nNumberOfBytesToRead;
    Function function           = info->function;
    info->retAddrOffset         = (size_t) drwrap_get_retaddr(wrapcxt) - baseAddr;

    // Identify whether this is the function we want to target
    bool targeted = client.isFunctionTargeted(function, info);
    client.incrementCallCountForFunction(function);

    // NOTE(ww): We should never read more bytes than we request, so this is more
    // of a sanity check than anything else.
    if (info->lpNumberOfBytesRead && *(info->lpNumberOfBytesRead) < nNumberOfBytesToRead) {
        nNumberOfBytesToRead = *(info->lpNumberOfBytesRead);
    }

    if (targeted) {
        if (!mutate(function, info->hFile, info->position, info->lpBuffer, nNumberOfBytesToRead)) {
            exit(1);
        }
    }

    if (info->argHash) {
        dr_thread_free(drcontext, info->argHash, SL2_HASH_LEN + 1);
    }

    dr_thread_free(drcontext, info, sizeof(client_read_info));
}

/* Runs when a new module (typically an exe or dll) is loaded. Tells DynamoRIO to hook all the interesting functions
    in that module. */
static void
on_module_load(void *drcontext, const module_data_t *mod, bool loaded)
{
    if (!strcmp(dr_get_application_name(), dr_module_preferred_name(mod))) {
        baseAddr = (uint64_t) mod->start;
    }

    const char *mod_name = dr_module_preferred_name(mod);
    app_pc towrap;

    sl2_pre_proto_map toHookPre;
    SL2_PRE_HOOK1(toHookPre, ReadFile);
    SL2_PRE_HOOK1(toHookPre, InternetReadFile);
    SL2_PRE_HOOK2(toHookPre, ReadEventLogA, ReadEventLog);
    SL2_PRE_HOOK2(toHookPre, ReadEventLogW, ReadEventLog);
    if( op_registry.get_value() ) {
        SL2_PRE_HOOK2(toHookPre, RegQueryValueExW, RegQueryValueEx);
        SL2_PRE_HOOK2(toHookPre, RegQueryValueExA, RegQueryValueEx);
    }
    SL2_PRE_HOOK1(toHookPre, WinHttpWebSocketReceive);
    SL2_PRE_HOOK1(toHookPre, WinHttpReadData);
    SL2_PRE_HOOK1(toHookPre, recv);
    SL2_PRE_HOOK1(toHookPre, fread_s);
    SL2_PRE_HOOK1(toHookPre, fread);
    SL2_PRE_HOOK1(toHookPre, _read);

    sl2_post_proto_map toHookPost;
    SL2_POST_HOOK2(toHookPost, ReadFile, Generic);
    SL2_POST_HOOK2(toHookPost, InternetReadFile, Generic);
    SL2_POST_HOOK2(toHookPost, ReadEventLogA, Generic);
    SL2_POST_HOOK2(toHookPost, ReadEventLogW, Generic);
    if( op_registry.get_value() ) {
        SL2_POST_HOOK2(toHookPost, RegQueryValueExW, Generic);
        SL2_POST_HOOK2(toHookPost, RegQueryValueExA, Generic);
    }
    SL2_POST_HOOK2(toHookPost, WinHttpWebSocketReceive, Generic);
    SL2_POST_HOOK2(toHookPost, WinHttpReadData, Generic);
    SL2_POST_HOOK2(toHookPost, recv, Generic);
    SL2_POST_HOOK2(toHookPost, fread_s, Generic);
    SL2_POST_HOOK2(toHookPost, fread, Generic);
    SL2_POST_HOOK2(toHookPost, _read, Generic);

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

    // Iterate over list of hooks and register them with DynamoRIO
    sl2_pre_proto_map::iterator it;
    for(it = toHookPre.begin(); it != toHookPre.end(); it++) {
        char *functionName = it->first;
        bool hook = false;

        if (!function_is_in_expected_module(functionName, mod_name)) {
            continue;
        }

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

        if (!hook) {
            continue;
        }

        void(__cdecl *hookFunctionPre)(void *, void **);
        hookFunctionPre = it->second;
        void(__cdecl *hookFunctionPost)(void *, void *);
        hookFunctionPost = NULL;

        // TODO(ww): Why do we do this, instead of just assigning above?
        if (toHookPost.find(functionName) != toHookPost.end()) {
            hookFunctionPost = toHookPost[functionName];
        }

        // Only hook ReadFile calls from the kernel (TODO - investigate fuzzgoat results)
        towrap = (app_pc) dr_get_proc_address(mod->handle, functionName);

        // If everything looks good and we've made it this far, wrap the function
        if (towrap != NULL) {
            dr_flush_region(towrap, 0x1000);
            bool ok = drwrap_wrap(towrap, hookFunctionPre, hookFunctionPost);
            if (ok) {
                SL2_DR_DEBUG("<wrapped %s @ 0x%p in %s\n", functionName, towrap, mod_name);
            } else {
                SL2_DR_DEBUG("<FAILED to wrap %s @ 0x%p: already wrapped?\n", functionName, towrap);
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

    drmgr_init();
    drwrap_init();

    drreg_options_t opts = {sizeof(opts), 3, false};
    drreg_init(&opts);

    // Check whether we can use coverage on this fuzzing run
    coverage_guided = client.areTargetsArenaCompatible() && !no_coverage;

    // Cache our main module, so that we don't have to retrieve it during each
    // basic block event.
    target_mod = dr_get_main_module();

    if (coverage_guided) {
        SL2_DR_DEBUG("dr_client_main: targets are arena compatible!\n");
        client.generateArenaId(arena.id);
        sl2_conn_request_arena(&sl2_conn, &arena);
        drmgr_register_bb_instrumentation_event(NULL, on_bb_instrument, NULL);
    }
    else {
        SL2_DR_DEBUG("dr_client_main: targets are NOT arena compatible OR user has requested dumb fuzzing!\n");
    }

    drmgr_register_exception_event(on_exception);
    dr_register_exit_event(on_dr_exit);
    drmgr_register_module_load_event(on_module_load);
}
