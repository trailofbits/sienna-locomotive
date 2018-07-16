#include <map>
#include <stdio.h>
#include <fstream>

#include <winsock2.h>
#include <winhttp.h>
#include <Windows.h>
#include <Winternl.h>
#include <Rpc.h>
#include <io.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"
#include "droption.h"

#include <picosha2.h>

#include "sl2_server_api.hpp"
#include "sl2_dr_client.hpp"

#ifdef WINDOWS
#define IF_WINDOWS_ELSE(x,y) x
#else
#define IF_WINDOWS_ELSE(x,y) y
#endif

#ifdef WINDOWS
#define DISPLAY_STRING(msg) dr_messagebox(msg)
#else
#define DISPLAY_STRING(msg) dr_printf("%s\n", msg);
#endif

#define NULL_TERMINATE(buf) buf[(sizeof(buf)/sizeof(buf[0])) - 1] = '\0'

static BOOL mutate(HANDLE hFile, size_t position, LPVOID buf, size_t size);

// structure for getting command line client options in dynamorio
static droption_t<std::string> op_target(
    DROPTION_SCOPE_CLIENT,
    "t",
    "",
    "targetfile",
    "JSON file in which to look for targets");

static SL2Client   client;
static sl2_client server_client;
static json parsedJson;
static BOOL crashed = false;
static DWORD64 baseAddr;
static DWORD mutateCount = 0;

// Metadata object for a target function call
struct fuzzer_read_info {
    Function function;
    HANDLE hFile;
    LPVOID lpBuffer;
    size_t nNumberOfBytesToRead;
    LPDWORD lpNumberOfBytesRead;
    DWORD64 position;
    DWORD64 retAddrOffset;
    // TODO(ww): Make this a WCHAR * for consistency.
    char *argHash;
};

/* Read the PEB of the target application and get the full command line */
static LPTSTR
get_target_command_line()
{
    // see: https://github.com/DynamoRIO/dynamorio/issues/2662
    // alternatively: https://wj32.org/wp/2009/01/24/howto-get-the-command-line-of-processes/
    _PEB * clientPEB = (_PEB *) dr_get_app_PEB();
    _RTL_USER_PROCESS_PARAMETERS parameterBlock;
    size_t byte_counter;

    // Read process parameter block from PEB
    if (!dr_safe_read(clientPEB->ProcessParameters, sizeof(_RTL_USER_PROCESS_PARAMETERS), &parameterBlock, &byte_counter)) {
        dr_log(NULL, DR_LOG_ALL, ERROR, "fuzzer#get_target_command_line: Could not read process parameter block");
        dr_exit_process(1);
    }

    // Allocate space for the command line
    WCHAR * commandLineContents = (WCHAR *)dr_global_alloc(parameterBlock.CommandLine.Length);

    // Read the command line from the parameter block
    if (!dr_safe_read(parameterBlock.CommandLine.Buffer, parameterBlock.CommandLine.Length, commandLineContents, &byte_counter)) {
        dr_log(NULL, DR_LOG_ALL, ERROR, "fuzzer#get_target_command_line: Could not read command line buffer");
        dr_exit_process(1);
    }

    return commandLineContents;
}

/* Maps exception code to an exit status. Print it out, then exit. */
static bool
onexception(void *drcontext, dr_exception_t *excpt)
{
    dr_log(NULL, DR_LOG_ALL, ERROR, "fuzzer#onexception: Exception occurred!\n");
    crashed = true;
    DWORD exceptionCode = excpt->record->ExceptionCode;

    switch (exceptionCode){
        case EXCEPTION_ACCESS_VIOLATION:
            SL2_DR_DEBUG("EXCEPTION_ACCESS_VIOLATION\n");
            break;
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            SL2_DR_DEBUG("EXCEPTION_ARRAY_BOUNDS_EXCEEDED\n");
            break;
        case EXCEPTION_BREAKPOINT:
            SL2_DR_DEBUG("EXCEPTION_BREAKPOINT\n");
            break;
        case EXCEPTION_DATATYPE_MISALIGNMENT:
            SL2_DR_DEBUG("EXCEPTION_DATATYPE_MISALIGNMENT\n");
            break;
        case EXCEPTION_FLT_DENORMAL_OPERAND:
            SL2_DR_DEBUG("EXCEPTION_FLT_DENORMAL_OPERAND\n");
            break;
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
            SL2_DR_DEBUG("EXCEPTION_FLT_DIVIDE_BY_ZERO\n");
            break;
        case EXCEPTION_FLT_INEXACT_RESULT:
            SL2_DR_DEBUG("EXCEPTION_FLT_INEXACT_RESULT\n");
            break;
        case EXCEPTION_FLT_INVALID_OPERATION:
            SL2_DR_DEBUG("EXCEPTION_FLT_INVALID_OPERATION\n");
            break;
        case EXCEPTION_FLT_OVERFLOW:
            SL2_DR_DEBUG("EXCEPTION_FLT_OVERFLOW\n");
            break;
        case EXCEPTION_FLT_STACK_CHECK:
            SL2_DR_DEBUG("EXCEPTION_FLT_STACK_CHECK\n");
            break;
        case EXCEPTION_FLT_UNDERFLOW:
            SL2_DR_DEBUG("EXCEPTION_FLT_UNDERFLOW\n");
            break;
        case EXCEPTION_ILLEGAL_INSTRUCTION:
            SL2_DR_DEBUG("EXCEPTION_ILLEGAL_INSTRUCTION\n");
            break;
        case EXCEPTION_IN_PAGE_ERROR:
            SL2_DR_DEBUG("EXCEPTION_IN_PAGE_ERROR\n");
            break;
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
            SL2_DR_DEBUG("EXCEPTION_INT_DIVIDE_BY_ZERO\n");
            break;
        case EXCEPTION_INT_OVERFLOW:
            SL2_DR_DEBUG("EXCEPTION_INT_OVERFLOW\n");
            break;
        case EXCEPTION_INVALID_DISPOSITION:
            SL2_DR_DEBUG("EXCEPTION_INVALID_DISPOSITION\n");
            break;
        case EXCEPTION_NONCONTINUABLE_EXCEPTION:
            SL2_DR_DEBUG("EXCEPTION_NONCONTINUABLE_EXCEPTION\n");
            break;
        case EXCEPTION_PRIV_INSTRUCTION:
            SL2_DR_DEBUG("EXCEPTION_PRIV_INSTRUCTION\n");
            break;
        case EXCEPTION_SINGLE_STEP:
            SL2_DR_DEBUG("EXCEPTION_SINGLE_STEP\n");
            break;
        case EXCEPTION_STACK_OVERFLOW:
            SL2_DR_DEBUG("EXCEPTION_STACK_OVERFLOW\n");
            break;
        default:
            break;
    }

    dr_exit_process(1);
    return true;
}

/* Runs after the target application has exited */
static void
event_exit(void)
{
    SL2_DR_DEBUG("Dynamorio exiting (fuzzer)\n");

    WCHAR run_id_s[SL2_UUID_SIZE];
    sl2_uuid_to_wstring(client.run_id, run_id_s);

    if (crashed) {
        SL2_DR_DEBUG("<crash found for run id %S>\n", run_id_s);
        dr_log(NULL, DR_LOG_ALL, ERROR, "fuzzer#event_exit: Crash found for run id %S!", run_id_s);
    }

    sl2_client_finalize_run(&client, crashed, false);
    sl2_client_close(&client);

    // Clean up DynamoRIO
    dr_log(NULL, DR_LOG_ALL, ERROR, "fuzzer#event_exit: Dynamorio Exiting\n");
    drwrap_exit();
    drmgr_exit();
}

/* Hands bytes off to the mutation server, gets mutated bytes, and writes them into memory. */
static BOOL
mutate(Function function, HANDLE hFile, size_t position, LPVOID buf, size_t size)
{
    WCHAR filePath[MAX_PATH + 1] = {0};

    // Check that ReadFile calls are to something actually valid
    // TODO(ww): Add fread and fread_s here once the _getosfhandle problem is fixed.
    if (function == Function::ReadFile) {
        if (hFile == INVALID_HANDLE_VALUE) {
            dr_log(NULL, DR_LOG_ALL, ERROR, "fuzzer#mutate: Invalid source for mutation?\n");
            return false;
        }

        GetFinalPathNameByHandle(hFile, filePath, MAX_PATH, 0);
        SL2_DR_DEBUG("mutate: filePath: %S", filePath);
    }

    DWORD type = static_cast<DWORD>(function);

    sl2_client_request_mutation(&client, type, mutateCount, filePath, position, size, buf);

    mutateCount++;

    return true;
}

/*
    drwrap_skip_call does not invoke the post function

    that means we need to cache the return value
    and properly set all the other variables in the call

    we also need to find out about stdcall arguments size
    for the functions we're hooking (so it can clean up)

    for things with file pointers, those need to be updated
    to the correct position

    make getlasterror work as expected

    on the server we need some mapping like below for the
    read / recevied bytes

    run_id ->
        command_line
    command_line ->
        function ->
            bytes

    std::map<DWORD, std::wstring> mapRunIdCommandLine;
    std::map<std::wstring, std::map<std::wstring, BYTE *>> mapCommandLineFunctionBytes;

    // set the cache in get run id
    std::wstring strCommandLine(commandLine);
    mapRunIdCommandLine[runId] = strCommandLine;

    // set the bytes in mutate
*/
/*
static BOOL
check_cache() {
    std::string target = op_target.get_value();
    if(target == "") {
        return false;
    }

    BOOL cached = false;
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

        BYTE event_id = //TODO;
        BOOL cached = false;

        WriteFile(h_pipe, &event_id, sizeof(BYTE), &bytes_written, NULL);
        WriteFile(h_pipe, &run_id, sizeof(DWORD), &bytes_written, NULL);
        WriteFile(h_pipe, target.c_str(), target.length(), , &bytes_written, NULL);
        ReadFile(h_pipe, &cached, sizeof(BOOL), &bytes_read, NULL);

        CloseHandle(h_pipe);
    }

    return cached;
}
//*/

/*
  The next several functions are wrappers that DynamoRIO calls before each of the targeted functions runs. Each of them
  records metadata about the target function call for use later.
*/

/*
    BOOL ReadEventLog(
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
    DWORD  dwReadFlags = (DWORD)drwrap_get_arg(wrapcxt, 1);
    DWORD  dwRecordOffset = (DWORD)drwrap_get_arg(wrapcxt, 2);
    LPVOID lpBuffer = (LPVOID)drwrap_get_arg(wrapcxt, 3);
    DWORD  nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 4);
    DWORD  *pnBytesRead = (DWORD *)drwrap_get_arg(wrapcxt, 5);
    DWORD  *pnMinNumberOfBytesNeeded = (DWORD *)drwrap_get_arg(wrapcxt, 6);

    *user_data             = malloc(sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::ReadEventLog;
    info->hFile                = hEventLog;
    info->lpBuffer             = lpBuffer;
    info->nNumberOfBytesToRead = nNumberOfBytesToRead;
    info->lpNumberOfBytesRead  = pnBytesRead;
    info->position             = 0;
    info->retAddrOffset        = (DWORD64) drwrap_get_retaddr(wrapcxt) - baseAddr;
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
        *user_data             = malloc(sizeof(client_read_info));
        client_read_info *info = (client_read_info *) *user_data;


        info->function             = Function::RegQueryValueEx;
        info->hFile                = hKey;
        info->lpBuffer             = lpData;
        info->nNumberOfBytesToRead = *lpcbData;
        info->lpNumberOfBytesRead  = lpcbData;
        info->position             = 0;
        info->retAddrOffset        = (DWORD64) drwrap_get_retaddr(wrapcxt) - baseAddr;
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
    DWORD dwBufferLength = (DWORD)drwrap_get_arg(wrapcxt, 2);
    PDWORD pdwBytesRead = (PDWORD)drwrap_get_arg(wrapcxt, 3);
    WINHTTP_WEB_SOCKET_BUFFER_TYPE peBufferType = (WINHTTP_WEB_SOCKET_BUFFER_TYPE)(int)drwrap_get_arg(wrapcxt, 3);

    // TODO: put this in another file cause you can't import wininet and winhttp
    // LONG positionHigh = 0;
    // DWORD positionLow = InternetSetFilePointer(hRequest, 0, &positionHigh, FILE_CURRENT);
    // DWORD64 position = positionHigh;

    *user_data             = malloc(sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::WinHttpWebSocketReceive;
    info->hFile                = hRequest;
    info->lpBuffer             = pvBuffer;
    info->nNumberOfBytesToRead = dwBufferLength;
    info->lpNumberOfBytesRead  = pdwBytesRead;
    info->position             = 0;
    info->retAddrOffset        = (DWORD64) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}

/*
    BOOL InternetReadFile(
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
    LPVOID lpBuffer = drwrap_get_arg(wrapcxt, 1);
    DWORD nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 2);
    LPDWORD lpNumberOfBytesRead = (LPDWORD)drwrap_get_arg(wrapcxt, 3);

    // LONG positionHigh = 0;
    // DWORD positionLow = InternetSetFilePointer(hFile, 0, &positionHigh, FILE_CURRENT);
    // DWORD64 position = positionHigh;

    *user_data             = malloc(sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::InternetReadFile;
    info->hFile                = hFile;
    info->lpBuffer             = lpBuffer;
    info->nNumberOfBytesToRead = nNumberOfBytesToRead;
    info->lpNumberOfBytesRead  = lpNumberOfBytesRead;
    info->position             = 0;
    info->retAddrOffset        = (DWORD64) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}

/*
    BOOL WINAPI WinHttpReadData(
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
    LPVOID lpBuffer = drwrap_get_arg(wrapcxt, 1);
    DWORD nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 2);
    LPDWORD lpNumberOfBytesRead = (LPDWORD)drwrap_get_arg(wrapcxt, 3);

    // LONG positionHigh = 0;
    // DWORD positionLow = InternetSetFilePointer(hRequest, 0, &positionHigh, FILE_CURRENT);
    // DWORD64 position = positionHigh;

    *user_data             = malloc(sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::WinHttpReadData;
    info->hFile                = hRequest;
    info->lpBuffer             = lpBuffer;
    info->nNumberOfBytesToRead = nNumberOfBytesToRead;
    info->lpNumberOfBytesRead  = lpNumberOfBytesRead;
    info->position             = 0;
    info->retAddrOffset        = (DWORD64) drwrap_get_retaddr(wrapcxt) - baseAddr;
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
    int len   = (int)drwrap_get_arg(wrapcxt, 2);
    int flags = (int)drwrap_get_arg(wrapcxt, 3);

    *user_data             = malloc(sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::recv;
    info->hFile                = NULL;
    info->lpBuffer             = buf;
    info->nNumberOfBytesToRead = len;
    info->lpNumberOfBytesRead  = NULL;
    info->position             = 0;
    info->retAddrOffset        = (DWORD64) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}

/*
    BOOL WINAPI ReadFile(
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
    LPVOID lpBuffer             = drwrap_get_arg(wrapcxt, 1);
    DWORD nNumberOfBytesToRead  = (DWORD)drwrap_get_arg(wrapcxt, 2);
    LPDWORD lpNumberOfBytesRead = (LPDWORD)drwrap_get_arg(wrapcxt, 3);

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

    *user_data             = malloc(sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::ReadFile;
    info->hFile                = hFile;
    info->lpBuffer             = lpBuffer;
    info->nNumberOfBytesToRead = nNumberOfBytesToRead;
    info->lpNumberOfBytesRead  = lpNumberOfBytesRead;
    info->position             = fStruct.position;
    info->retAddrOffset        = (DWORD64) drwrap_get_retaddr(wrapcxt) - baseAddr;

    // NOTE(ww): SHA2 digests are 64 characters, so we allocate that + room for a NULL
    info->argHash = (char *) malloc(65);
    memset(info->argHash, 0, 65);
    memcpy(info->argHash, hash_str.c_str(), 64);
}

static void
wrap_pre_fread_s(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_fread_s>\n");
    void *buffer = (void *)drwrap_get_arg(wrapcxt, 0);
    size_t size  = (size_t)drwrap_get_arg(wrapcxt, 2);
    size_t count = (size_t)drwrap_get_arg(wrapcxt, 3);
    FILE *file   = (FILE *)drwrap_get_arg(wrapcxt, 4);

    *user_data             = malloc(sizeof(client_read_info));
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
    size_t size  = (size_t)drwrap_get_arg(wrapcxt, 1);
    size_t count = (size_t)drwrap_get_arg(wrapcxt, 2);
    FILE *file   = (FILE *)drwrap_get_arg(wrapcxt, 3);

    *user_data             = malloc(sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::fread;
    // TODO(ww): Figure out why _get_osfhandle breaks DR.
    // info->hFile             = (HANDLE) _get_osfhandle(_fileno(file));
    info->hFile                = NULL;
    info->lpBuffer             = buffer;
    info->nNumberOfBytesToRead = size * count;
    info->lpNumberOfBytesRead  = NULL;
    info->position             = NULL;
    info->retAddrOffset        = (DWORD64) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}


/* Mutates whatever data the hooked function wrote */
static void
wrap_post_Generic(void *wrapcxt, void *user_data)
{

    SL2_DR_DEBUG("<in wrap_post_Generic>\n");
    if (user_data == NULL) {
        return;
    }

    client_read_info *info = (client_read_info *) user_data;

    // Grab stored metadata
    size_t nNumberOfBytesToRead = info->nNumberOfBytesToRead;
    Function function           = info->function;
    info->retAddrOffset       = (size_t) drwrap_get_retaddr(wrapcxt) - baseAddr;

    // Identify whether this is the function we want to target
    BOOL targeted = client.isFunctionTargeted( function, info );
    client.incrementCallCountForFunction(function);

    if (info->lpNumberOfBytesRead) {
        nNumberOfBytesToRead = *info->lpNumberOfBytesRead;
    }

    // Talk to the server and mutate the bytes
    if (targeted) {
        if (!mutate(function, info->hFile, info->position, info->lpBuffer, nNumberOfBytesToRead)) {
            // TODO: fallback mutations?
            exit(1);
        }
    }

    if (info->argHash) {
        free(info->argHash);
    }

    free(info);
}

/* Runs when a new module (typically an exe or dll) is loaded. Tells DynamoRIO to hook all the interesting functions
    in that module. */
static void
module_load_event(void *drcontext, const module_data_t *mod, bool loaded)
{
    if (!strcmp(dr_get_application_name(), dr_module_preferred_name(mod))) {
        baseAddr = (DWORD64) mod->start;
    }

    // Build list of pre-function hooks
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

    // Build list of post-function hooks
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

    // Iterate over list of hooks and register them with DynamoRIO
    std::map<char *, SL2_PRE_PROTO>::iterator it;
    for(it = toHookPre.begin(); it != toHookPre.end(); it++) {
        char *functionName = it->first;
        bool hook = false;

        // Look for function matching the target specified on the command line
        std::string strFunctionName(functionName);

        for (targetFunction t : client.parsedJson) {
            if (t.selected && t.functionName == strFunctionName){
                hook = true;
            }
            else if (t.selected && (strFunctionName == "RegQueryValueExW" || strFunctionName == "RegQueryValueExA")) {
                if (t.functionName != "RegQueryValueEx") {
                  hook = false;
                }
            }
        }

        printf("%s: %d\n", functionName, hook);

        if (!hook)
          continue;

        void(__cdecl *hookFunctionPre)(void *, void **);
        hookFunctionPre = it->second;
        void(__cdecl *hookFunctionPost)(void *, void *);
        hookFunctionPost = NULL;

        if (toHookPost.find(functionName) != toHookPost.end()) {
            hookFunctionPost = toHookPost[functionName];
        }

        // Only hook ReadFile calls from the kernel (TODO - investigate fuzzgoat results)
        app_pc towrap = (app_pc) dr_get_proc_address(mod->handle, functionName);
        const char *mod_name = dr_module_preferred_name(mod);

        if (strFunctionName == "ReadFile") {
            if (_stricmp(mod_name, "KERNELBASE.dll") != 0) {
                continue;
            }
        }

        // Only hook registry queries in the kernel
        if (strFunctionName == "RegQueryValueExA" or strFunctionName == "RegQueryValueExW") {
            if (_stricmp(mod_name, "KERNELBASE.dll") != 0) {
                continue;
            }
        }

        // Only hook fread(_s) calls from the C runtime
        if (strFunctionName == "fread" || strFunctionName == "fread_s") {
            if (_stricmp(mod_name, "UCRTBASE.DLL") != 0) {
                continue;
            }
        }

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

/*
    instrument_bb

    is first instr
    get module names == target
    insert clean call
*/

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
        SL2_DR_DEBUG("ERROR: arg -t (target file) required");
        dr_abort();
    }

    try {
        client.loadJson(target);
    } catch (const char* msg) {
        SL2_DR_DEBUG(msg);
        dr_abort();
    }

    // Set up console printing
    dr_log(NULL, DR_LOG_ALL, 1, "DR client 'SL Fuzzer' initializing\n");
    if (dr_is_notify_on()) {
#ifdef WINDOWS
        dr_enable_console_printing();  // TODO - necessary?
#endif
        dr_log(NULL, DR_LOG_ALL, ERROR, "Client SL Fuzzer is running\n");
    }

    //TODO: support multiple passes over one binary without re-running drrun

    // Get application name
    const char* mbsAppName = dr_get_application_name();
    WCHAR wcsAppName[MAX_PATH];
    mbstowcs(wcsAppName, mbsAppName, MAX_PATH);

    sl2_client_open(&client);
    sl2_client_request_run_id(&client, wcsAppName, get_target_command_line());

    WCHAR run_id_s[SL2_UUID_SIZE];
    sl2_uuid_to_wstring(client.run_id, run_id_s);
    // Initialize DynamoRIO and register callbacks
    SL2_DR_DEBUG("Beginning fuzzing run %S\n\n", run_id_s);
    drmgr_init();
    drwrap_init();

    drmgr_register_exception_event(onexception);
    dr_register_exit_event(event_exit);
    drmgr_register_module_load_event(module_load_event);
}
