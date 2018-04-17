#include <map>

#include <stdio.h>

#include <winsock2.h>
#include <winhttp.h>
#include <Windows.h>
#include <Winternl.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"
#include "droption.h"


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


static droption_t<std::string> op_include(
    DROPTION_SCOPE_CLIENT, 
    "i", 
    "", 
    "include",
    "Functions to be included in hooking.");

static droption_t<std::string> op_target(
    DROPTION_SCOPE_CLIENT, 
    "t", 
    "", 
    "target",
    "Specific call to target.");


enum class Function {
    ReadFile,
    recv,
    WinHttpReadData,
    InternetReadFile,
    WinHttpWebSocketReceive,
    RegQueryValueEx,
    ReadEventLog,
};

DWORD runId;
BOOL crashed = false;

std::map<Function, UINT64> call_counts;

char *get_function_name(Function function) {
    switch(function) {
        case Function::ReadFile:
            return "ReadFile";
        case Function::recv:
            return "recv";
        case Function::WinHttpReadData:
            return "WinHttpReadData";
        case Function::InternetReadFile:
            return "InternetReadFile";
        case Function::WinHttpWebSocketReceive:
            return "WinHttpWebSocketReceive";
        case Function::RegQueryValueEx:
            return "RegQueryValueEx";
        case Function::ReadEventLog:
            return "ReadEventLog";
    }

    return "unknown";
}

//TODO: Fix logging 
DWORD getRunID(HANDLE hPipe, LPCTSTR targetName, LPTSTR targetArgs) {
    dr_log(NULL, LOG_ALL, ERROR, "Requesting run id");
    DWORD bytesRead = 0;
    DWORD bytesWritten = 0;

    BYTE eventId = 0;
    DWORD runId = 0;
    if (!TransactNamedPipe(hPipe, &eventId, sizeof(BYTE), &runId, sizeof(DWORD), &bytesRead, NULL)) {
        dr_log(NULL, LOG_ALL, ERROR, "Error getting run id (%x)", GetLastError());
        dr_exit_process(1);
    }

    DWORD size = lstrlen(targetName) * sizeof(TCHAR);
    if (!WriteFile(hPipe, &size, sizeof(DWORD), &bytesWritten, NULL)) {
        dr_log(NULL, LOG_ALL, ERROR, "Error getting run id (%x)", GetLastError());
        dr_exit_process(1);
    }

    if (!WriteFile(hPipe, targetName, size, &bytesWritten, NULL)) {
        dr_log(NULL, LOG_ALL, ERROR, "Error getting run id (%x)", GetLastError());
        dr_exit_process(1);
    }

    size = lstrlen(targetArgs) * sizeof(TCHAR);
    if (!WriteFile(hPipe, &size, sizeof(DWORD), &bytesWritten, NULL)) {
        dr_log(NULL, LOG_ALL, ERROR, "Error getting run id (%x)", GetLastError());
        dr_exit_process(1);
    }

    if (!WriteFile(hPipe, targetArgs, size, &bytesWritten, NULL)) {
        dr_log(NULL, LOG_ALL, ERROR, "Error getting run id (%x)", GetLastError());
        dr_exit_process(1);
    }

    dr_log(NULL, LOG_ALL, ERROR, "Run id %x", runId);

    return runId;
}

HANDLE getPipe() {
    HANDLE hPipe;
    while (1) {
        hPipe = CreateFile(
            "\\\\.\\pipe\\fuzz_server",
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);

        if (hPipe != INVALID_HANDLE_VALUE) {
            break;
        }

        DWORD err = GetLastError();
        if (err != ERROR_PIPE_BUSY) {
            dr_log(NULL, LOG_ALL, ERROR, "Could not open pipe (%x)", err);
            dr_fprintf(STDERR, "Could not open pipe (0x%x)\n", err);
            dr_fprintf(STDERR, "Is the server running?\n");
            dr_exit_process(1);
        }

        if (!WaitNamedPipe("\\\\.\\pipe\\fuzz_server", 5000)) {
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

DWORD finalize(HANDLE hPipe, DWORD runId, BOOL crashed) {
    if (crashed) {
        dr_fprintf(STDERR, "<crash found for run id %d>\n", runId);
        dr_log(NULL, LOG_ALL, ERROR, "Crash found for run id %d!", runId);
    }

    DWORD bytesWritten;
    BYTE eventId = 4;

    if (!WriteFile(hPipe, &eventId, sizeof(BYTE), &bytesWritten, NULL)) {
        dr_log(NULL, LOG_ALL, ERROR, "Error finalizing (%x)", GetLastError());
        dr_exit_process(1);
    }

    if (!WriteFile(hPipe, &runId, sizeof(DWORD), &bytesWritten, NULL)) {
        dr_log(NULL, LOG_ALL, ERROR, "Error finalizing (%x)", GetLastError());
        dr_exit_process(1);
    }

    if (!WriteFile(hPipe, &crashed, sizeof(BOOL), &bytesWritten, NULL)) {
        dr_log(NULL, LOG_ALL, ERROR, "Error finalizing (%x)", GetLastError());
        dr_exit_process(1);
    }

    return 0;
}

static LPTSTR 
get_target_command_line() {
    // see: https://github.com/DynamoRIO/dynamorio/issues/2662
    // alternatively: https://wj32.org/wp/2009/01/24/howto-get-the-command-line-of-processes/
    _PEB * clientPEB = (_PEB *) dr_get_app_PEB();
    _RTL_USER_PROCESS_PARAMETERS parameterBlock;
    size_t byte_counter;

    if (!dr_safe_read(clientPEB->ProcessParameters, sizeof(_RTL_USER_PROCESS_PARAMETERS), &parameterBlock, &byte_counter)) {
        dr_log(NULL, LOG_ALL, ERROR, "Could not read process parameter block");
        dr_exit_process(1);
    }

    WCHAR * commandLineContents = (WCHAR *)dr_global_alloc(parameterBlock.CommandLine.Length);
    char * mbsCommandLineContents;

    if (dr_safe_read(parameterBlock.CommandLine.Buffer, parameterBlock.CommandLine.Length, commandLineContents, &byte_counter)) {
        size_t outSize = 0;
        if(wcstombs_s(&outSize, NULL, 0, commandLineContents, parameterBlock.CommandLine.Length)) {
            dr_log(NULL, LOG_ALL, ERROR, "Could not get length of command line");
            dr_exit_process(1);
        }

        mbsCommandLineContents = (char *)dr_global_alloc(outSize);
        if(wcstombs_s(&byte_counter, mbsCommandLineContents, outSize, commandLineContents, parameterBlock.CommandLine.Length)) {
            dr_log(NULL, LOG_ALL, ERROR, "Could not convert command line");
            dr_exit_process(1);
        }

        dr_global_free(commandLineContents, parameterBlock.CommandLine.Length);
    } else {
        dr_log(NULL, LOG_ALL, ERROR, "Could not read command line buffer");
        dr_exit_process(1);
    }

  return mbsCommandLineContents;
}

static bool
onexception(void *drcontext, dr_exception_t *excpt) {
    dr_log(NULL, LOG_ALL, ERROR, "Exception occurred!\n");

    crashed = true;
    DWORD exceptionCode = excpt->record->ExceptionCode;

    switch (exceptionCode){
        case EXCEPTION_ACCESS_VIOLATION:
            dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_ACCESS_VIOLATION");
            break;
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_ARRAY_BOUNDS_EXCEEDED");
            break;
        case EXCEPTION_BREAKPOINT:
            dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_BREAKPOINT");
            break;
        case EXCEPTION_DATATYPE_MISALIGNMENT:
            dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_DATATYPE_MISALIGNMENT");
            break;
        case EXCEPTION_FLT_DENORMAL_OPERAND:
            dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_FLT_DENORMAL_OPERAND");
            break;
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
            dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_FLT_DIVIDE_BY_ZERO");
            break;
        case EXCEPTION_FLT_INEXACT_RESULT:
            dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_FLT_INEXACT_RESULT");
            break;
        case EXCEPTION_FLT_INVALID_OPERATION:
            dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_FLT_INVALID_OPERATION");
            break;
        case EXCEPTION_FLT_OVERFLOW:
            dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_FLT_OVERFLOW");
            break;
        case EXCEPTION_FLT_STACK_CHECK:
            dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_FLT_STACK_CHECK");
            break;
        case EXCEPTION_FLT_UNDERFLOW:
            dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_FLT_UNDERFLOW");
            break;
        case EXCEPTION_ILLEGAL_INSTRUCTION:
            dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_ILLEGAL_INSTRUCTION");
            break;
        case EXCEPTION_IN_PAGE_ERROR:
            dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_IN_PAGE_ERROR");
            break;
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
            dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_INT_DIVIDE_BY_ZERO");
            break;
        case EXCEPTION_INT_OVERFLOW:
            dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_INT_OVERFLOW");
            break;
        case EXCEPTION_INVALID_DISPOSITION:
            dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_INVALID_DISPOSITION");
            break;
        case EXCEPTION_NONCONTINUABLE_EXCEPTION:
            dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_NONCONTINUABLE_EXCEPTION");
            break;
        case EXCEPTION_PRIV_INSTRUCTION:
            dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_PRIV_INSTRUCTION");
            break;
        case EXCEPTION_SINGLE_STEP:
            dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_SINGLE_STEP");
            break;
        case EXCEPTION_STACK_OVERFLOW:
            dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_STACK_OVERFLOW");
            break;
        default:
            break;
    }

    dr_exit_process(1);
    return true;
}

/* from wrap.cpp sample code */
static void
event_exit(void) {
    HANDLE hPipe = getPipe();
    finalize(hPipe, runId, crashed);
    CloseHandle(hPipe);

    dr_log(NULL, LOG_ALL, ERROR, "Dynamorio Exiting\n");
    drwrap_exit();
    drmgr_exit();
}

/* Hands bytes off to the mutation server, gets mutated bytes, and writes them into memory. */
static DWORD mutateCount = 0;

static BOOL 
mutate(Function function, HANDLE hFile, DWORD64 position, LPVOID buf, DWORD size) {
    TCHAR filePath[MAX_PATH+1];
    TCHAR *new_buf = (TCHAR *)buf;
    DWORD pathSize = 0;

    if(function == Function::ReadFile) {
        if (hFile == INVALID_HANDLE_VALUE) {
            dr_log(NULL, LOG_ALL, ERROR, "The file we're trying to read from doesn't appear to be valid\n");
            return false;
        }

        pathSize = GetFinalPathNameByHandle(hFile, filePath, MAX_PATH, 0);

        if (pathSize > MAX_PATH || pathSize == 0) {
            dr_log(NULL, LOG_ALL, ERROR, "Pathsize %d is out of bounds\n", pathSize);
            return false;
        }
    }

    
    filePath[pathSize] = 0;
    
    HANDLE hPipe = getPipe();
    
    DWORD bytesRead = 0;
    DWORD bytesWritten = 0;
    
    BYTE eventId = 1;
    DWORD type = static_cast<DWORD>(function);
    
    // Send state information to the fuzz server
    WriteFile(hPipe, &eventId, sizeof(BYTE), &bytesWritten, NULL);
    WriteFile(hPipe, &runId, sizeof(DWORD), &bytesWritten, NULL);
    WriteFile(hPipe, &type, sizeof(DWORD), &bytesWritten, NULL);
    WriteFile(hPipe, &mutateCount, sizeof(DWORD), &bytesWritten, NULL);
    
    WriteFile(hPipe, &pathSize, sizeof(DWORD), &bytesWritten, NULL);
    WriteFile(hPipe, &filePath, pathSize * sizeof(TCHAR), &bytesWritten, NULL);
    
    WriteFile(hPipe, &position, sizeof(DWORD64), &bytesWritten, NULL);
    WriteFile(hPipe, &size, sizeof(DWORD), &bytesWritten, NULL);
      
    // Send current contents of buf to the server, overwrite them with its reply
    TransactNamedPipe(hPipe, buf, size, buf, size, &bytesRead, NULL);
    
    CloseHandle(hPipe);
    
    mutateCount++;

  return true;
}

struct read_info {
    Function function;
    HANDLE hFile;
    LPVOID lpBuffer;
    DWORD nNumberOfBytesToRead;
    LPDWORD lpNumberOfBytesRead;
    DWORD64 position;
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
    ((read_info *)*user_data)->function = Function::ReadEventLog;
    ((read_info *)*user_data)->hFile = hEventLog;
    ((read_info *)*user_data)->lpBuffer = lpBuffer;
    ((read_info *)*user_data)->nNumberOfBytesToRead = nNumberOfBytesToRead;
    ((read_info *)*user_data)->lpNumberOfBytesRead = pnBytesRead;
    ((read_info *)*user_data)->position = 0;
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

/* from wrap.cpp sample code. Runs before ReadFile is called. Records arguments to
   ReadFile and stores them in probably thread-unsafe variables above. */
static void
wrap_pre_ReadFile(void *wrapcxt, OUT void **user_data) {
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

/* Called after ReadFile returns. Calls `mutate` on the bytes that ReadFile
   wrote into the program's memory. */
static void
wrap_post_Generic(void *wrapcxt, void *user_data) {
    if(user_data == NULL) {
        return;
    }

    read_info *info = ((read_info *)user_data);

    Function function = info->function;
    HANDLE hFile = info->hFile;
    LPVOID lpBuffer = info->lpBuffer;
    DWORD nNumberOfBytesToRead = info->nNumberOfBytesToRead;
    LPDWORD lpNumberOfBytesRead = info->lpNumberOfBytesRead;
    DWORD64 position = info->position;
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

    if (lpNumberOfBytesRead) {
        nNumberOfBytesToRead = *lpNumberOfBytesRead;
    }
    
    if(targeted) {
        if (!mutate(function, hFile, position, lpBuffer, nNumberOfBytesToRead)) {
            // TODO: fallback mutations?
            exit(1);
        }
    }
}

static void
module_load_event(void *drcontext, const module_data_t *mod, bool loaded) {
    // void(__cdecl *)(void *, OUT void **)
#define PREPROTO void(__cdecl *)(void *, void **)
#define POSTPROTO void(__cdecl *)(void *, void *)

    std::map<char *, PREPROTO> toHookPre;
    toHookPre["ReadFile"] = wrap_pre_ReadFile;
    toHookPre["InternetReadFile"] = wrap_pre_InternetReadFile;
    toHookPre["ReadEventLog"] = wrap_pre_ReadEventLog;
    toHookPre["RegQueryValueExW"] = wrap_pre_RegQueryValueEx;
    toHookPre["RegQueryValueExA"] = wrap_pre_RegQueryValueEx;
    toHookPre["WinHttpWebSocketReceive"] = wrap_pre_WinHttpWebSocketReceive;
    toHookPre["WinHttpReadData"] = wrap_pre_WinHttpReadData;
    toHookPre["recv"] = wrap_pre_recv;
    
    std::map<char *, POSTPROTO> toHookPost;
    toHookPost["ReadFile"] = wrap_post_Generic;
    toHookPost["InternetReadFile"] = wrap_post_Generic;
    toHookPost["ReadEventLog"] = wrap_post_Generic;
    toHookPost["RegQueryValueExW"] = wrap_post_Generic;
    toHookPost["RegQueryValueExA"] = wrap_post_Generic;
    toHookPost["WinHttpWebSocketReceive"] = wrap_post_Generic;
    toHookPost["WinHttpReadData"] = wrap_post_Generic;
    toHookPost["recv"] = wrap_post_Generic;

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
                dr_fprintf(STDERR, "<wrapped %s @ 0x%p in %s\n", functionName, towrap, mod_name);
            } else {
                dr_fprintf(STDERR, "<FAILED to wrap %s @ 0x%p: already wrapped?\n", functionName, towrap);
            }
        }
    }
}

/* Runs after process initialization. Initializes DynamoRIO and registers module load callback*/
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    dr_set_client_name("Sienna-Locomotive Fuzzer",
                       "https://github.com/trailofbits/sienna-locomotive/issues");

    std::string parse_err;
    int last_idx = 0;
    if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, &parse_err, &last_idx)) {
        dr_fprintf(STDERR, "Usage error: %s", parse_err.c_str());
        dr_abort();
    }

    dr_log(NULL, LOG_ALL, 1, "DR client 'SL Fuzzer' initializing\n");
    if (dr_is_notify_on()) {
#ifdef WINDOWS
        dr_enable_console_printing();
#endif
        dr_log(NULL, LOG_ALL, ERROR, "Client SL Fuzzer is running\n");
    }

    //TODO: support multiple passes over one binary without re-running drrun

    HANDLE hPipe = getPipe();
    runId = getRunID(hPipe, dr_get_application_name(), get_target_command_line());
    CloseHandle(hPipe);

    drmgr_init();
    drwrap_init();
    
    max_ReadFile = 0;

    drmgr_register_exception_event(onexception);
    dr_register_exit_event(event_exit);
    drmgr_register_module_load_event(module_load_event);
}