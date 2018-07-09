#include <map>
#include <stdio.h>
#include <fstream>

#include <winsock2.h>
#include <winhttp.h>
#include <Windows.h>
#include <Winternl.h>
#include <Rpc.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"
#include "droption.h"

#include <json.hpp>
using json = nlohmann::json;

extern "C" {
    #include "common/uuid.h"
}

#include "server.hpp"
#include "common/function_lookup.hpp"

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

static size_t max_ReadFile;
static void *max_lock; /* sync writes to max_ReadFile */

static BOOL mutate(HANDLE hFile, DWORD64 position, LPVOID buf, DWORD size);

// structure for getting command line client options in dynamorio
static droption_t<std::string> op_target(
    DROPTION_SCOPE_CLIENT,
    "t",
    "",
    "targetfile",
    "JSON file in which to look for targets");

struct targetFunction {
  bool selected;
  UINT64 index;
  UINT64 mode;
  std::string functionName;
};

// TODO throw error messages if this doesn't work
void from_json(const json& j, targetFunction& t) {
    t.selected = j.at("selected").get<bool>();
    t.index = j.at("callCount").get<int>();
    t.mode = j.at("mode").get<int>();
    t.functionName = j.at("func_name").get<std::string>();
}

json parsedJson;

UUID runId;
BOOL crashed = false;

std::map<Function, UINT64> call_counts;

//TODO: Fix logging
/* Tries to get a new Run ID from the fuzz server */
UUID getRunID(HANDLE hPipe, LPCTSTR targetName, LPTSTR targetArgs) {
    dr_log(NULL, LOG_ALL, ERROR, "Requesting run id");
    DWORD bytesRead = 0;
    DWORD bytesWritten = 0;

    BYTE eventId = EVT_RUN_ID;
    UUID runId;
    if (!TransactNamedPipe(hPipe, &eventId, sizeof(BYTE), &runId, sizeof(UUID), &bytesRead, NULL)) {
        dr_log(NULL, LOG_ALL, ERROR, "Error getting run id (%x)", GetLastError());
        dr_exit_process(1);
    }

    WCHAR runId_s[SL2_UUID_SIZE];
    sl2_uuid_to_wstring(runId, runId_s);

    dr_log(NULL, LOG_ALL, ERROR, "Run id %S", runId_s);

    DWORD size = lstrlenW(targetName) * sizeof(WCHAR);

    if (!WriteFile(hPipe, &size, sizeof(DWORD), &bytesWritten, NULL)) {
        dr_log(NULL, LOG_ALL, ERROR, "Error getting run id (%x)", GetLastError());
        dr_exit_process(1);
    }

    if (!WriteFile(hPipe, targetName, size, &bytesWritten, NULL)) {
        dr_log(NULL, LOG_ALL, ERROR, "Error getting run id (%x)", GetLastError());
        dr_exit_process(1);
    }

    size = lstrlen(targetArgs) * sizeof(WCHAR);
    if (!WriteFile(hPipe, &size, sizeof(DWORD), &bytesWritten, NULL)) {
        dr_log(NULL, LOG_ALL, ERROR, "Error getting run id (%x)", GetLastError());
        dr_exit_process(1);
    }

    if (!WriteFile(hPipe, targetArgs, size, &bytesWritten, NULL)) {
        dr_log(NULL, LOG_ALL, ERROR, "Error getting run id (%x)", GetLastError());
        dr_exit_process(1);
    }

    return runId;
}

/* Get a handle to the pipe that lets us talk to the server */
HANDLE getPipe() {
    HANDLE hPipe;
    while (1) {
        hPipe = CreateFile(
            FUZZ_SERVER_PATH,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);

        if (hPipe != INVALID_HANDLE_VALUE) {
            break;
        }

        // This is basically just a check that the server is running
        DWORD err = GetLastError();
        if (err != ERROR_PIPE_BUSY) {
            dr_log(NULL, LOG_ALL, ERROR, "Could not open pipe (%x)", err);
            dr_fprintf(STDERR, "Could not open pipe (0x%x)\n", err);
            dr_fprintf(STDERR, "Is the server running?\n");
            dr_exit_process(1);
        }

        if (!WaitNamedPipe(FUZZ_SERVER_PATH, 5000)) {
            dr_log(NULL, LOG_ALL, ERROR, "Could not connect, timeout");
            dr_fprintf(STDERR, "Could not connect, timeout\n", err);
            dr_exit_process(1);
        }
    }

    DWORD readMode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(
        hPipe,
        &readMode,
        NULL,
        NULL);

    return hPipe;
}

/* Close out the fuzzing run with the server */
DWORD finalize(HANDLE hPipe, UUID runId, BOOL crashed) {
    WCHAR runId_s[SL2_UUID_SIZE];
    sl2_uuid_to_wstring(runId, runId_s);
    if (crashed) {
        dr_fprintf(STDERR, "<crash found for run id %S>\n", runId_s);
        dr_log(NULL, LOG_ALL, ERROR, "Crash found for run id %S!", runId_s);
    }

    DWORD bytesWritten;
    BYTE eventId = EVT_RUN_COMPLETE;

    // write the event ID (4 for finalize)
    if (!WriteFile(hPipe, &eventId, sizeof(BYTE), &bytesWritten, NULL)) {
        dr_log(NULL, LOG_ALL, ERROR, "Error finalizing (%x)", GetLastError());
        dr_exit_process(1);
    }
    // Write the run ID
    if (!WriteFile(hPipe, &runId, sizeof(UUID), &bytesWritten, NULL)) {
        dr_log(NULL, LOG_ALL, ERROR, "Error finalizing (%x)", GetLastError());
        dr_exit_process(1);
    }
     // write whether the run found a crash
    if (!WriteFile(hPipe, &crashed, sizeof(BOOL), &bytesWritten, NULL)) {
        dr_log(NULL, LOG_ALL, ERROR, "Error finalizing (%x)", GetLastError());
        dr_exit_process(1);
    }

    return 0;
}

/* Read the PEB of the target application and get the full command line */
static LPTSTR
get_target_command_line() {
    // see: https://github.com/DynamoRIO/dynamorio/issues/2662
    // alternatively: https://wj32.org/wp/2009/01/24/howto-get-the-command-line-of-processes/
    _PEB * clientPEB = (_PEB *) dr_get_app_PEB();
    _RTL_USER_PROCESS_PARAMETERS parameterBlock;
    size_t byte_counter;

    // Read process parameter block from PEB
    if (!dr_safe_read(clientPEB->ProcessParameters, sizeof(_RTL_USER_PROCESS_PARAMETERS), &parameterBlock, &byte_counter)) {
        dr_log(NULL, LOG_ALL, ERROR, "Could not read process parameter block");
        dr_exit_process(1);
    }

    // Allocate space for the command line
    WCHAR * commandLineContents = (WCHAR *)dr_global_alloc(parameterBlock.CommandLine.Length);

    // Read the command line from the parameter block
    if (!dr_safe_read(parameterBlock.CommandLine.Buffer, parameterBlock.CommandLine.Length, commandLineContents, &byte_counter)) {
        dr_log(NULL, LOG_ALL, ERROR, "Could not read command line buffer");
        dr_exit_process(1);
    }

  return commandLineContents;
}

/* Maps exception code to an exit status. Print it out, then exit. */
static bool
onexception(void *drcontext, dr_exception_t *excpt) {
    dr_log(NULL, LOG_ALL, ERROR, "Exception occurred!\n");

    crashed = true;
    DWORD exceptionCode = excpt->record->ExceptionCode;

    switch (exceptionCode){
        case EXCEPTION_ACCESS_VIOLATION:
            dr_fprintf(STDERR, "EXCEPTION_ACCESS_VIOLATION\n");
            break;
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            dr_fprintf(STDERR, "EXCEPTION_ARRAY_BOUNDS_EXCEEDED\n");
            break;
        case EXCEPTION_BREAKPOINT:
            dr_fprintf(STDERR, "EXCEPTION_BREAKPOINT\n");
            break;
        case EXCEPTION_DATATYPE_MISALIGNMENT:
            dr_fprintf(STDERR, "EXCEPTION_DATATYPE_MISALIGNMENT\n");
            break;
        case EXCEPTION_FLT_DENORMAL_OPERAND:
            dr_fprintf(STDERR, "EXCEPTION_FLT_DENORMAL_OPERAND\n");
            break;
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
            dr_fprintf(STDERR, "EXCEPTION_FLT_DIVIDE_BY_ZERO\n");
            break;
        case EXCEPTION_FLT_INEXACT_RESULT:
            dr_fprintf(STDERR, "EXCEPTION_FLT_INEXACT_RESULT\n");
            break;
        case EXCEPTION_FLT_INVALID_OPERATION:
            dr_fprintf(STDERR, "EXCEPTION_FLT_INVALID_OPERATION\n");
            break;
        case EXCEPTION_FLT_OVERFLOW:
            dr_fprintf(STDERR, "EXCEPTION_FLT_OVERFLOW\n");
            break;
        case EXCEPTION_FLT_STACK_CHECK:
            dr_fprintf(STDERR, "EXCEPTION_FLT_STACK_CHECK\n");
            break;
        case EXCEPTION_FLT_UNDERFLOW:
            dr_fprintf(STDERR, "EXCEPTION_FLT_UNDERFLOW\n");
            break;
        case EXCEPTION_ILLEGAL_INSTRUCTION:
            dr_fprintf(STDERR, "EXCEPTION_ILLEGAL_INSTRUCTION\n");
            break;
        case EXCEPTION_IN_PAGE_ERROR:
            dr_fprintf(STDERR, "EXCEPTION_IN_PAGE_ERROR\n");
            break;
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
            dr_fprintf(STDERR, "EXCEPTION_INT_DIVIDE_BY_ZERO\n");
            break;
        case EXCEPTION_INT_OVERFLOW:
            dr_fprintf(STDERR, "EXCEPTION_INT_OVERFLOW\n");
            break;
        case EXCEPTION_INVALID_DISPOSITION:
            dr_fprintf(STDERR, "EXCEPTION_INVALID_DISPOSITION\n");
            break;
        case EXCEPTION_NONCONTINUABLE_EXCEPTION:
            dr_fprintf(STDERR, "EXCEPTION_NONCONTINUABLE_EXCEPTION\n");
            break;
        case EXCEPTION_PRIV_INSTRUCTION:
            dr_fprintf(STDERR, "EXCEPTION_PRIV_INSTRUCTION\n");
            break;
        case EXCEPTION_SINGLE_STEP:
            dr_fprintf(STDERR, "EXCEPTION_SINGLE_STEP\n");
            break;
        case EXCEPTION_STACK_OVERFLOW:
            dr_fprintf(STDERR, "EXCEPTION_STACK_OVERFLOW\n");
            break;
        default:
            break;
    }

    dr_exit_process(1);
    return true;
}

/* Runs after the target application has exited */
static void
event_exit(void) {
    HANDLE hPipe = getPipe();
    finalize(hPipe, runId, crashed); // Delete the fuzzing run if we didn't find a crash
    CloseHandle(hPipe); // Close out connection to server

    // Clean up DynamoRIO
    dr_log(NULL, LOG_ALL, ERROR, "Dynamorio Exiting\n");
    drwrap_exit();
    drmgr_exit();
}

/* Hands bytes off to the mutation server, gets mutated bytes, and writes them into memory. */
static DWORD mutateCount = 0;
static BOOL
mutate(Function function, HANDLE hFile, DWORD64 position, LPVOID buf, DWORD size) {
    WCHAR filePath[MAX_PATH+1];
    WCHAR *new_buf = (WCHAR *)buf;
    DWORD pathSize = 0;

    // Check that ReadFile calls are to something actually valid
    if(function == Function::ReadFile) {
        if (hFile == INVALID_HANDLE_VALUE) {
            dr_log(NULL, LOG_ALL, ERROR, "The file we're trying to read from doesn't appear to be valid\n");
            return false;
        }

        pathSize = GetFinalPathNameByHandle(hFile, filePath, MAX_PATH, 0);

        if (pathSize > MAX_PATH || pathSize == 0) {
            dr_fprintf(STDERR, "pathSize out of bounds\n");
            dr_log(NULL, LOG_ALL, ERROR, "Pathsize %d is out of bounds\n", pathSize);
            return false;
        }

        dr_fprintf(STDERR, "FILE PATH: %s\n", filePath);
    }

    // initialize output variables
    filePath[pathSize] = 0;

    HANDLE hPipe = getPipe();

    DWORD bytesRead = 0;
    DWORD bytesWritten = 0;

    BYTE eventId = EVT_MUTATION;
    DWORD type = static_cast<DWORD>(function);

    // Send state information to the fuzz server
    WriteFile(hPipe, &eventId, sizeof(BYTE), &bytesWritten, NULL);
    WriteFile(hPipe, &runId, sizeof(UUID), &bytesWritten, NULL);
    WriteFile(hPipe, &type, sizeof(DWORD), &bytesWritten, NULL);
    WriteFile(hPipe, &mutateCount, sizeof(DWORD), &bytesWritten, NULL);

    WriteFile(hPipe, &pathSize, sizeof(DWORD), &bytesWritten, NULL);
    WriteFile(hPipe, &filePath, pathSize * sizeof(WCHAR), &bytesWritten, NULL);

    WriteFile(hPipe, &position, sizeof(DWORD64), &bytesWritten, NULL);
    WriteFile(hPipe, &size, sizeof(DWORD), &bytesWritten, NULL);

    // Send current contents of buf to the server, overwrite them with its reply
    TransactNamedPipe(hPipe, buf, size, buf, size, &bytesRead, NULL);

    CloseHandle(hPipe);

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

// Metadata object for a target function call
struct read_info {
    Function function;
    HANDLE hFile;
    LPVOID lpBuffer;
    DWORD nNumberOfBytesToRead;
    LPDWORD lpNumberOfBytesRead;
    DWORD64 position;
};

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
    ((read_info *)*user_data)->function = Function::ReadEventLog;
    ((read_info *)*user_data)->hFile = hEventLog;
    ((read_info *)*user_data)->lpBuffer = lpBuffer;
    ((read_info *)*user_data)->nNumberOfBytesToRead = nNumberOfBytesToRead;
    ((read_info *)*user_data)->lpNumberOfBytesRead = pnBytesRead;
    ((read_info *)*user_data)->position = 0;
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
        ((read_info *)*user_data)->function = Function::RegQueryValueEx;
        ((read_info *)*user_data)->hFile = hKey;
        ((read_info *)*user_data)->lpBuffer = lpData;
        ((read_info *)*user_data)->nNumberOfBytesToRead = *lpcbData;
        ((read_info *)*user_data)->lpNumberOfBytesRead = lpcbData;
        ((read_info *)*user_data)->position = 0;
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
wrap_pre_WinHttpWebSocketReceive(void *wrapcxt, OUT void **user_data) {
    dr_fprintf(STDERR, "<in wrap_pre_WinHttpWebSocketReceive>\n");
    HINTERNET hRequest = (HINTERNET)drwrap_get_arg(wrapcxt, 0);
    PVOID pvBuffer = drwrap_get_arg(wrapcxt, 1);
    DWORD dwBufferLength = (DWORD)drwrap_get_arg(wrapcxt, 2);
    PDWORD pdwBytesRead = (PDWORD)drwrap_get_arg(wrapcxt, 3);
    WINHTTP_WEB_SOCKET_BUFFER_TYPE peBufferType = (WINHTTP_WEB_SOCKET_BUFFER_TYPE)(int)drwrap_get_arg(wrapcxt, 3);

    // TODO: put this in another file cause you can't import wininet and winhttp
    // LONG positionHigh = 0;
    // DWORD positionLow = InternetSetFilePointer(hRequest, 0, &positionHigh, FILE_CURRENT);
    // DWORD64 position = positionHigh;

    *user_data = malloc(sizeof(read_info));
    ((read_info *)*user_data)->function = Function::WinHttpWebSocketReceive;
    ((read_info *)*user_data)->hFile = hRequest;
    ((read_info *)*user_data)->lpBuffer = pvBuffer;
    ((read_info *)*user_data)->nNumberOfBytesToRead = dwBufferLength;
    ((read_info *)*user_data)->lpNumberOfBytesRead = pdwBytesRead;
    ((read_info *)*user_data)->position = 0;
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
wrap_pre_InternetReadFile(void *wrapcxt, OUT void **user_data) {
    dr_fprintf(STDERR, "<in wrap_pre_InternetReadFile>\n");
    HINTERNET hFile = (HINTERNET)drwrap_get_arg(wrapcxt, 0);
    LPVOID lpBuffer = drwrap_get_arg(wrapcxt, 1);
    DWORD nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 2);
    LPDWORD lpNumberOfBytesRead = (LPDWORD)drwrap_get_arg(wrapcxt, 3);

    // LONG positionHigh = 0;
    // DWORD positionLow = InternetSetFilePointer(hFile, 0, &positionHigh, FILE_CURRENT);
    // DWORD64 position = positionHigh;

    *user_data = malloc(sizeof(read_info));
    ((read_info *)*user_data)->function = Function::InternetReadFile;
    ((read_info *)*user_data)->hFile = hFile;
    ((read_info *)*user_data)->lpBuffer = lpBuffer;
    ((read_info *)*user_data)->nNumberOfBytesToRead = nNumberOfBytesToRead;
    ((read_info *)*user_data)->lpNumberOfBytesRead = lpNumberOfBytesRead;
    ((read_info *)*user_data)->position = 0;
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
wrap_pre_WinHttpReadData(void *wrapcxt, OUT void **user_data) {
    dr_fprintf(STDERR, "<in wrap_pre_WinHttpReadData>\n");
    HINTERNET hRequest = (HINTERNET)drwrap_get_arg(wrapcxt, 0);
    LPVOID lpBuffer = drwrap_get_arg(wrapcxt, 1);
    DWORD nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 2);
    LPDWORD lpNumberOfBytesRead = (LPDWORD)drwrap_get_arg(wrapcxt, 3);

    // LONG positionHigh = 0;
    // DWORD positionLow = InternetSetFilePointer(hRequest, 0, &positionHigh, FILE_CURRENT);
    // DWORD64 position = positionHigh;

    *user_data = malloc(sizeof(read_info));
    ((read_info *)*user_data)->function = Function::WinHttpReadData;
    ((read_info *)*user_data)->hFile = hRequest;
    ((read_info *)*user_data)->lpBuffer = lpBuffer;
    ((read_info *)*user_data)->nNumberOfBytesToRead = nNumberOfBytesToRead;
    ((read_info *)*user_data)->lpNumberOfBytesRead = lpNumberOfBytesRead;
    ((read_info *)*user_data)->position = 0;
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
wrap_pre_recv(void *wrapcxt, OUT void **user_data) {
    dr_fprintf(STDERR, "<in wrap_pre_recv>\n");
    SOCKET s = (SOCKET)drwrap_get_arg(wrapcxt, 0);
    char *buf = (char *)drwrap_get_arg(wrapcxt, 1);
    int len = (int)drwrap_get_arg(wrapcxt, 2);
    int flags = (int)drwrap_get_arg(wrapcxt, 3);

    *user_data = malloc(sizeof(read_info));
    ((read_info *)*user_data)->function = Function::recv;
    ((read_info *)*user_data)->hFile = NULL;
    ((read_info *)*user_data)->lpBuffer = buf;
    ((read_info *)*user_data)->nNumberOfBytesToRead = len;
    ((read_info *)*user_data)->lpNumberOfBytesRead = NULL;
    ((read_info *)*user_data)->position = 0;
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
wrap_pre_ReadFile(void *wrapcxt, OUT void **user_data) {
    dr_fprintf(STDERR, "<in wrap_pre_ReadFile>\n");
    HANDLE hFile = drwrap_get_arg(wrapcxt, 0);
    LPVOID lpBuffer = drwrap_get_arg(wrapcxt, 1);
    DWORD nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 2);
    LPDWORD lpNumberOfBytesRead = (LPDWORD)drwrap_get_arg(wrapcxt, 3);

    LONG positionHigh = 0;
    DWORD positionLow = SetFilePointer(hFile, 0, &positionHigh, FILE_CURRENT);
    DWORD64 position = positionHigh;

    *user_data = malloc(sizeof(read_info));
    ((read_info *)*user_data)->function = Function::ReadFile;
    ((read_info *)*user_data)->hFile = hFile;
    ((read_info *)*user_data)->lpBuffer = lpBuffer;
    ((read_info *)*user_data)->nNumberOfBytesToRead = nNumberOfBytesToRead;
    ((read_info *)*user_data)->lpNumberOfBytesRead = lpNumberOfBytesRead;
    ((read_info *)*user_data)->position = (position << 32) | positionLow;
}

// TODO fill out this function prototype
static void
wrap_pre_fread(void *wrapcxt, OUT void **user_data) {
    dr_fprintf(STDERR, "<in wrap_pre_fread>\n");
    void *buffer = (void *)drwrap_get_arg(wrapcxt, 0);
    size_t size = (size_t)drwrap_get_arg(wrapcxt, 1);
    size_t count = (size_t)drwrap_get_arg(wrapcxt, 2);

    *user_data = malloc(sizeof(read_info));
    ((read_info *)*user_data)->function = Function::fread;
    ((read_info *)*user_data)->hFile = NULL;
    ((read_info *)*user_data)->lpBuffer = buffer;
    ((read_info *)*user_data)->nNumberOfBytesToRead = size * count;
    ((read_info *)*user_data)->lpNumberOfBytesRead = NULL;
    ((read_info *)*user_data)->position = NULL;
}

/* Mutates whatever data the hooked function wrote */
static void
wrap_post_Generic(void *wrapcxt, void *user_data) {
    if(user_data == NULL) {
        return;
    }

    read_info *info = ((read_info *)user_data);

    // Record the metadata about this function call
    Function function = info->function;
    HANDLE hFile = info->hFile;
    LPVOID lpBuffer = info->lpBuffer;
    DWORD nNumberOfBytesToRead = info->nNumberOfBytesToRead;
    LPDWORD lpNumberOfBytesRead = info->lpNumberOfBytesRead;
    DWORD64 position = info->position;
    free(user_data);

    // Double check that this is the specific function call we're supposed to be targeting
    BOOL targeted = false;
    std::string strFunctionName(get_function_name(function));
    for (targetFunction t: parsedJson){
      if (t.selected and t.functionName == strFunctionName and call_counts[function] == t.index){
        targeted = true;
      }
    }
    call_counts[function]++; // increment the call counter

    if (lpNumberOfBytesRead) {
        nNumberOfBytesToRead = *lpNumberOfBytesRead;
    }

    // Talk to the server and mutate the bytes
    if(targeted) {
        if (!mutate(function, hFile, position, lpBuffer, nNumberOfBytesToRead)) {
            // TODO: fallback mutations?
            exit(1);
        }
    }
}

/* Runs when a new module (typically an exe or dll) is loaded. Tells DynamoRIO to hook all the interesting functions
    in that module. */
static void
module_load_event(void *drcontext, const module_data_t *mod, bool loaded) {
    // void(__cdecl *)(void *, OUT void **)
#define PREPROTO void(__cdecl *)(void *, void **)
#define POSTPROTO void(__cdecl *)(void *, void *)

    // Build list of pre-function hooks
    std::map<char *, PREPROTO> toHookPre;
    toHookPre["ReadFile"] = wrap_pre_ReadFile;
    toHookPre["InternetReadFile"] = wrap_pre_InternetReadFile;
    toHookPre["ReadEventLog"] = wrap_pre_ReadEventLog;
    toHookPre["RegQueryValueExW"] = wrap_pre_RegQueryValueEx;
    toHookPre["RegQueryValueExA"] = wrap_pre_RegQueryValueEx;
    toHookPre["WinHttpWebSocketReceive"] = wrap_pre_WinHttpWebSocketReceive;
    toHookPre["WinHttpReadData"] = wrap_pre_WinHttpReadData;
    toHookPre["recv"] = wrap_pre_recv;
    toHookPre["fread"] = wrap_pre_fread;

    // Build list of post-function hooks
    std::map<char *, POSTPROTO> toHookPost;
    toHookPost["ReadFile"] = wrap_post_Generic;
    toHookPost["InternetReadFile"] = wrap_post_Generic;
    toHookPost["ReadEventLog"] = wrap_post_Generic;
    toHookPost["RegQueryValueExW"] = wrap_post_Generic;
    toHookPost["RegQueryValueExA"] = wrap_post_Generic;
    toHookPost["WinHttpWebSocketReceive"] = wrap_post_Generic;
    toHookPost["WinHttpReadData"] = wrap_post_Generic;
    toHookPost["recv"] = wrap_post_Generic;
    toHookPost["fread"] = wrap_post_Generic;

    // Iterate over list of hooks and register them with DynamoRIO
    std::map<char *, PREPROTO>::iterator it;
    for(it = toHookPre.begin(); it != toHookPre.end(); it++) {
        char *functionName = it->first;
        bool hook = false;

        // Look for function matching the target specified on the command line
        std::string strFunctionName(functionName);
        for (targetFunction t: parsedJson){
          if (t.selected and t.functionName == strFunctionName){
            hook = true;
          }
          else if(t.selected and (strFunctionName == "RegQueryValueExW" or strFunctionName == "RegQueryValueExA")) {
            if(t.functionName != "RegQueryValueEx") {
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

        if(toHookPost.find(functionName) != toHookPost.end()) {
            hookFunctionPost = toHookPost[functionName];
        }

        // Only hook ReadFile calls from the kernel (TODO - investigate fuzzgoat results)
        app_pc towrap = (app_pc) dr_get_proc_address(mod->handle, functionName);
        const char *mod_name = dr_module_preferred_name(mod);
        if(strFunctionName == "ReadFile") {
            if(strcmp(mod_name, "KERNELBASE.dll") != 0) {
                continue;
            }
        }

        // Only hook registry queries in the kernel
        if(strFunctionName == "RegQueryValueExA" or strFunctionName == "RegQueryValueExW") {
            if(strcmp(mod_name, "KERNELBASE.dll") != 0) {
                continue;
            }
        }

        // If everything looks good and we've made it this far, wrap the function
        if (towrap != NULL) {
            dr_flush_region(towrap, 0x1000);
            bool ok = drwrap_wrap(towrap, hookFunctionPre, hookFunctionPost);
            // bool ok = false;
            if (ok) {
                dr_fprintf(STDERR, "<wrapped %s @ 0x%p in %s\n", functionName, towrap, mod_name);
            } else {
                dr_fprintf(STDERR, "<FAILED to wrap %s @ 0x%p: already wrapped?\n", functionName, towrap);
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
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    dr_set_client_name("Sienna-Locomotive Fuzzer",
                       "https://github.com/trailofbits/sienna-locomotive/issues");

    // Parse command line options
    std::string parse_err;
    int last_idx = 0;
    if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, &parse_err, &last_idx)) {
        dr_fprintf(STDERR, "Usage error: %s", parse_err.c_str());
        dr_abort();
    }

    std::string target = op_target.get_value();
    if(target == "") {
        dr_fprintf(STDERR, "ERROR: arg -t (target file) required");
        dr_abort();
    }

    std::ifstream jsonStream(target); // TODO ifstream can sometimes cause performance issues
    jsonStream >> parsedJson;
    if (!parsedJson.is_array())
      dr_fprintf(STDERR, "Document root is not an array\n");

    // Set up console printing
    dr_log(NULL, LOG_ALL, 1, "DR client 'SL Fuzzer' initializing\n");
    if (dr_is_notify_on()) {
#ifdef WINDOWS
        dr_enable_console_printing();  // TODO - necessary?
#endif
        dr_log(NULL, LOG_ALL, ERROR, "Client SL Fuzzer is running\n");
    }

    //TODO: support multiple passes over one binary without re-running drrun

    // Get application name
    HANDLE hPipe = getPipe();
    const char* mbsAppName = dr_get_application_name();
    WCHAR wcsAppName[MAX_PATH];
    mbstowcs(wcsAppName, mbsAppName, MAX_PATH);

    // Send application name and invokation to fuzz server, get back the run ID
    runId = getRunID(hPipe, wcsAppName, get_target_command_line());
    CloseHandle(hPipe);

    WCHAR runId_s[SL2_UUID_SIZE];
    sl2_uuid_to_wstring(runId, runId_s);
    // Initialize DynamoRIO and register callbacks
    dr_fprintf(STDERR, "Beginning fuzzing run %S\n\n", runId_s);
    drmgr_init();
    drwrap_init();

    max_ReadFile = 0;

    drmgr_register_exception_event(onexception);
    dr_register_exit_event(event_exit);
    drmgr_register_module_load_event(module_load_event);
}
