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

#include <Dbghelp.h>
#include <Windows.h>
#include <winsock2.h>
#include <winhttp.h>

#include <iostream>
#include <codecvt>
#include <locale>

#include <json.hpp>
using json = nlohmann::json;
using namespace std;

#include "common/function_lookup.hpp"

////////////////////////////////////////////////////////////////////////////
// logObject()
//
// Takes a json object and prints it to stderr for consumption by the harness
////////////////////////////////////////////////////////////////////////////
void logObject( json obj )
{
    auto str = obj.dump();

    // TODO(ww): Replace this with a separate channel for JSON.
    // NOTE(ww): This loop is here because dr_fprintf has an internal buffer
    // of 2048, and our JSON objects frequently exceed that. When that happens,
    // dr_fprintf silently truncates them and confuses the harness with invalid JSON.
    // We circumvent this by chunking the output.
    for (int i = 0; i < str.length(); i += 1024) {
        dr_fprintf(STDERR, "%s", str.substr(i, 1024).c_str());
    }

    dr_fprintf(STDERR, "\n");
}

/* Run whenever a thread inits/exits */
static void
event_thread_init(void *drcontext)
{

}

static void
event_thread_exit(void *drcontext)
{

}

/* Clean up after the target binary exits */
static void
event_exit_trace(void)
{
    if (!drmgr_unregister_thread_init_event(event_thread_init) ||
        !drmgr_unregister_thread_exit_event(event_thread_exit) ||
        drreg_exit() != DRREG_SUCCESS)
    {
        DR_ASSERT(false);
    }

    drmgr_exit();
}


std::map<Function, UINT64> call_counts;

// function metadata structure
struct read_info {
    LPVOID lpBuffer;
    size_t nNumberOfBytesToRead;
    Function function;
    TCHAR *source;
    DWORD position;
    PBYTE caller;
};

/*
Below we have a number of functions that instrument metadata retreival for the individual functions we can hook.
*/

// TODO: hook functions that open the handles for these
//       so we can track the names of the resources geing read

static void
wrap_pre_ReadEventLog(void *wrapcxt, OUT void **user_data) {

    json j;
    j["type"]       = "in";
    j["function"]   = "wrap_pre_ReadEventLog";
    logObject(j);

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
    ((read_info *)*user_data)->source = NULL;
    ((read_info *)*user_data)->position = NULL;
}


static void
wrap_pre_RegQueryValueEx(void *wrapcxt, OUT void **user_data) {
    json j;
    j["type"]       = "in";
    j["function"]   = "wrap_pre_RegQueryValueEx";
    logObject(j);


    HKEY    hKey = (HKEY)drwrap_get_arg(wrapcxt, 0);
    LPCTSTR lpValueName = (LPCTSTR)drwrap_get_arg(wrapcxt, 1);
    LPDWORD lpReserved = (LPDWORD)drwrap_get_arg(wrapcxt, 2);
    LPDWORD lpType = (LPDWORD)drwrap_get_arg(wrapcxt, 3);
    LPBYTE  lpData = (LPBYTE)drwrap_get_arg(wrapcxt, 4);
    LPDWORD lpcbData = (LPDWORD)drwrap_get_arg(wrapcxt, 5);

    // get registry key path (maybe hook open key?)

    if(lpData != NULL && lpcbData != NULL) {
        *user_data = malloc(sizeof(read_info));
        ((read_info *)*user_data)->lpBuffer = lpData;
        ((read_info *)*user_data)->nNumberOfBytesToRead = *lpcbData;
        ((read_info *)*user_data)->function = Function::RegQueryValueEx;
        ((read_info *)*user_data)->source = NULL;
        ((read_info *)*user_data)->position = NULL;
    } else {
        *user_data = NULL;
    }
}

static void
wrap_pre_WinHttpWebSocketReceive(void *wrapcxt, OUT void **user_data) {
    json j;
    j["type"]       = "in";
    j["function"]   = "wrap_pre_WinHttpWebSocketReceive";
    logObject(j);

    HINTERNET hRequest = (HINTERNET)drwrap_get_arg(wrapcxt, 0);
    PVOID pvBuffer = drwrap_get_arg(wrapcxt, 1);
    DWORD dwBufferLength = (DWORD)drwrap_get_arg(wrapcxt, 2);
    PDWORD pdwBytesRead = (PDWORD)drwrap_get_arg(wrapcxt, 3);
    WINHTTP_WEB_SOCKET_BUFFER_TYPE peBufferType = (WINHTTP_WEB_SOCKET_BUFFER_TYPE)(int)drwrap_get_arg(wrapcxt, 3);

    // get url
    // InternetQueryOption

    *user_data = malloc(sizeof(read_info));
    ((read_info *)*user_data)->lpBuffer = pvBuffer;
    ((read_info *)*user_data)->nNumberOfBytesToRead = dwBufferLength;
    ((read_info *)*user_data)->function = Function::WinHttpWebSocketReceive;
    ((read_info *)*user_data)->source = NULL;
    ((read_info *)*user_data)->position = NULL;
}

static void
wrap_pre_InternetReadFile(void *wrapcxt, OUT void **user_data) {
    json j;
    j["type"]       = "in";
    j["function"]   = "wrap_pre_InternetReadFile";
    logObject(j);

    HINTERNET hFile = (HINTERNET)drwrap_get_arg(wrapcxt, 0);
    LPVOID lpBuffer = drwrap_get_arg(wrapcxt, 1);
    DWORD nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 2);
    LPDWORD lpNumberOfBytesRead = (LPDWORD)drwrap_get_arg(wrapcxt, 3);

    // get url
    // InternetQueryOption

    *user_data = malloc(sizeof(read_info));
    ((read_info *)*user_data)->lpBuffer = lpBuffer;
    ((read_info *)*user_data)->nNumberOfBytesToRead = nNumberOfBytesToRead;
    ((read_info *)*user_data)->function = Function::InternetReadFile;
    ((read_info *)*user_data)->source = NULL;
    ((read_info *)*user_data)->position = NULL;
}

static void
wrap_pre_WinHttpReadData(void *wrapcxt, OUT void **user_data) {
    json j;
    j["type"]       = "in";
    j["function"]   = "wrap_pre_WinHttpReadData";
    logObject(j);

    HINTERNET hRequest = (HINTERNET)drwrap_get_arg(wrapcxt, 0);
    LPVOID lpBuffer = drwrap_get_arg(wrapcxt, 1);
    DWORD nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 2);
    LPDWORD lpNumberOfBytesRead = (LPDWORD)drwrap_get_arg(wrapcxt, 3);

    // get url
    // InternetQueryOption

    *user_data = malloc(sizeof(read_info));
    ((read_info *)*user_data)->lpBuffer = lpBuffer;
    ((read_info *)*user_data)->nNumberOfBytesToRead = nNumberOfBytesToRead;
    ((read_info *)*user_data)->function = Function::WinHttpReadData;
    ((read_info *)*user_data)->source = NULL;
    ((read_info *)*user_data)->position = NULL;
}

static void
wrap_pre_recv(void *wrapcxt, OUT void **user_data) {
    json j;
    j["type"]       = "in";
    j["function"]   = "wrap_pre_recv";
    logObject(j);

    SOCKET s = (SOCKET)drwrap_get_arg(wrapcxt, 0);
    char *buf = (char *)drwrap_get_arg(wrapcxt, 1);
    int len = (int)drwrap_get_arg(wrapcxt, 2);
    int flags = (int)drwrap_get_arg(wrapcxt, 3);

    // get ip address
    // getpeername

    *user_data = malloc(sizeof(read_info));
    ((read_info *)*user_data)->lpBuffer = buf;
    ((read_info *)*user_data)->nNumberOfBytesToRead = len;
    ((read_info *)*user_data)->function = Function::recv;
    ((read_info *)*user_data)->source = NULL;
    ((read_info *)*user_data)->position = NULL;

    // get peer name doesn't work
    // https://github.com/DynamoRIO/dynamorio/issues/1883

    // struct sockaddr_in peer;
    // int peer_len = sizeof(peer);
    // getpeername(s, (sockaddr *)&peer, &peer_len);
    // dr_printf("Peer's IP address is: %s\n", inet_ntoa(peer.sin_addr));
    // dr_printf("Peer's port is: %d\n", (int) ntohs(peer.sin_port));
}

static void
wrap_pre_ReadFile(void *wrapcxt, OUT void **user_data) {
    json j;
    j["type"]       = "in";
    j["function"]   = "wrap_pre_ReadFile";
    logObject(j);

    dr_mcontext_t* dynamorio_context = drwrap_get_mcontext(wrapcxt);
    HANDLE hFile = drwrap_get_arg(wrapcxt, 0);
    LPVOID lpBuffer = drwrap_get_arg(wrapcxt, 1);
    DWORD nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 2);
    LPDWORD lpNumberOfBytesRead = (LPDWORD)drwrap_get_arg(wrapcxt, 3);

    *user_data = malloc(sizeof(read_info));
    ((read_info *)*user_data)->lpBuffer = lpBuffer;
    ((read_info *)*user_data)->nNumberOfBytesToRead = nNumberOfBytesToRead;
    ((read_info *)*user_data)->function = Function::ReadFile;
    ((read_info *)*user_data)->source = NULL;
    ((read_info *)*user_data)->position = NULL;
    ((read_info *)*user_data)->caller = dynamorio_context->rip;
    dr_fprintf(STDERR, "\nRIP: 0x%x\n\n", dynamorio_context);

    LPWSTR filePath = (LPWSTR)malloc(sizeof(WCHAR) * (MAX_PATH+1));
    DWORD pathSize = GetFinalPathNameByHandle(hFile, filePath, MAX_PATH, FILE_NAME_NORMALIZED);
    ((read_info *)*user_data)->source = filePath;
    ((read_info *)*user_data)->position = SetFilePointer(hFile, 0, NULL, FILE_CURRENT);
}

static void
wrap_pre_fread(void *wrapcxt, OUT void **user_data) {
    json j;
    j["type"]       = "in";
    j["function"]   = "wrap_pre_fread";
    logObject(j);

    void *buffer = (void *)drwrap_get_arg(wrapcxt, 0);
    size_t size = (size_t)drwrap_get_arg(wrapcxt, 1);
    size_t count = (size_t)drwrap_get_arg(wrapcxt, 2);

    *user_data = malloc(sizeof(read_info));
    ((read_info *)*user_data)->lpBuffer = buffer;
    ((read_info *)*user_data)->nNumberOfBytesToRead = size * count;
    ((read_info *)*user_data)->function = Function::fread;
    ((read_info *)*user_data)->source = NULL;
    ((read_info *)*user_data)->position = NULL;
}

static void
wrap_pre_fread_s(void *wrapcxt, OUT void **user_data) {
    json j;
    j["type"]       = "in";
    j["function"]   = "wrap_pre_fread_s";
    logObject(j);

    void *buffer = (void *)drwrap_get_arg(wrapcxt, 0);
    size_t size = (size_t)drwrap_get_arg(wrapcxt, 2);
    size_t count = (size_t)drwrap_get_arg(wrapcxt, 3);

    *user_data = malloc(sizeof(read_info));
    ((read_info *)*user_data)->lpBuffer = buffer;
    ((read_info *)*user_data)->nNumberOfBytesToRead = size * count;
    ((read_info *)*user_data)->function = Function::fread_s;
    ((read_info *)*user_data)->source = NULL;
    ((read_info *)*user_data)->position = NULL;
}

/* helper function for dumping memory contents to stderr */
// static void
// hex_dump(LPVOID lpBuffer, DWORD nNumberOfBytesToRead) {
//     DWORD size = nNumberOfBytesToRead > 256 ? 256 : nNumberOfBytesToRead;

//     for(DWORD i = 0; i < size; i++) {
//         BYTE ch = ((BYTE *)lpBuffer)[i];

//         if(i % 16 == 0) {
//             if(i != 0) {
//                 dr_fprintf(STDERR, "|");
//                 for(DWORD j = i - 16; j < i; j++) {
//                     BYTE pch = ((BYTE *)lpBuffer)[j];
//                     if(pch > 0x1f && pch < 0x7f) {
//                         dr_fprintf(STDERR, "%c", pch);
//                     } else {
//                         dr_fprintf(STDERR, ".");
//                     }
//                 }
//                 dr_fprintf(STDERR, "\n");
//             }
//             dr_fprintf(STDERR, "%4d | ", i);

//         }
//         dr_fprintf(STDERR, "%02X ", ch);
//     }

//     DWORD i = size;
//     while(i % 16 != 0) {
//         dr_fprintf(STDERR, "   ");
//         i++;
//     }

//     if(i != 0) {
//         dr_fprintf(STDERR, "|");
//         for(DWORD j = i - 16; j < i && j < size; j++) {
//             BYTE pch = ((BYTE *)lpBuffer)[j];
//             if(pch > 0x1f && pch < 0x7f) {
//                 dr_fprintf(STDERR, "%c", pch);
//             } else {
//                 dr_fprintf(STDERR, ".");
//             }
//         }
//         dr_fprintf(STDERR, "\n");
//     }
//     dr_fprintf(STDERR, "\n");
// }

/* prints information about the function call to stderr so the harness can ingest it */
static void
wrap_post_Generic(void *wrapcxt, void *user_data) {
    if(user_data == NULL) {
        return;
    }

    read_info *info = ((read_info *)user_data);
    CHAR *functionName = get_function_name(info->function);

    json j;
    j["type"]               = "id";
    j["callCount"]          = call_counts[info->function];
    j["caller"]             = (UINT64) info->caller;

    // TODO(ww): Fix the ,-prefixing that happens on some function names.
    j["func_name"] = functionName[0] == ',' ? functionName + 1 : functionName;

    call_counts[info->function]++;

    if(info->source != NULL) {
        wstring_convert<std::codecvt_utf8<wchar_t>> utf8Convert;
        wstring wstr =  wstring(info->source);
        j["source"] = utf8Convert.to_bytes(wstr);
        free(info->source);
        size_t end = info->position + info->nNumberOfBytesToRead;
        j["start"]  = info->position;
        j["end"]    = end;
    }

    LPVOID lpBuffer = info->lpBuffer;
    size_t nNumberOfBytesToRead = info->nNumberOfBytesToRead;
    free(user_data);

    vector<unsigned char> x;
    x.resize(nNumberOfBytesToRead);
    memcpy( &x[0], lpBuffer, nNumberOfBytesToRead );
    j["buffer"]  = x;

    logObject(j);
}

/* Runs every time we load a new module. Wraps functions we can target. See fuzzer.cpp for a more-detailed version */
static void
module_load_event(void *drcontext, const module_data_t *mod, bool loaded) {
#define PREPROTO void(__cdecl *)(void *, void **)
#define POSTPROTO void(__cdecl *)(void *, void *)

    /*
        ReadFile is hooked twice, in kernel32 and kernelbase.
        kernelbase is forwarded to kernel32, so if we want to filter
            to only one hook make sure we hook kernel32.
    */

    std::map<char *, PREPROTO> toHookPre;
    toHookPre["ReadEventLog"] = wrap_pre_ReadEventLog;
    toHookPre["RegQueryValueExW"] = wrap_pre_RegQueryValueEx;
    toHookPre["RegQueryValueExA"] = wrap_pre_RegQueryValueEx;
    toHookPre["WinHttpWebSocketReceive"] = wrap_pre_WinHttpWebSocketReceive;
    toHookPre["InternetReadFile"] = wrap_pre_InternetReadFile;
    toHookPre["WinHttpReadData"] = wrap_pre_WinHttpReadData;
    toHookPre["recv"] = wrap_pre_recv;
    toHookPre["ReadFile"] = wrap_pre_ReadFile;
    toHookPre["fread_s"] = wrap_pre_fread_s;
    toHookPre["fread"] = wrap_pre_fread;

    std::map<char *, POSTPROTO> toHookPost;
    toHookPost["ReadFile"] = wrap_post_Generic;
    toHookPost["InternetReadFile"] = wrap_post_Generic;
    toHookPost["ReadEventLog"] = wrap_post_Generic;
    toHookPost["RegQueryValueExW"] = wrap_post_Generic;
    toHookPost["RegQueryValueExA"] = wrap_post_Generic;
    toHookPost["WinHttpWebSocketReceive"] = wrap_post_Generic;
    toHookPost["WinHttpReadData"] = wrap_post_Generic;
    toHookPost["recv"] = wrap_post_Generic;
    toHookPost["fread_s"] = wrap_post_Generic;
    toHookPost["fread"] = wrap_post_Generic;

    std::map<char *, PREPROTO>::iterator it;
    for(it = toHookPre.begin(); it != toHookPre.end(); it++) {
        char *functionName = it->first;
        std::string strFunctionName(functionName);

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
                json j;
                j["type"]           = "wrapped";
                // TODO(ww): Fix the ,-prefixing that happens on some function names.
                j["func_name"] = functionName[0] == ',' ? functionName + 1 : functionName;
                j["toWrap"]         = (uint64_t)towrap;
                j["modName"]        = mod_name;
                logObject(j);
            } else {
                json j;
                j["type"] = "error";
                ostringstream s;
                s << "FAILED to wrap " << functionName <<  " @ " << towrap << " already wrapped?";
                j["msg"] = s.str();
                logObject(j);
            }
        }
    }
}

/* registers event callbacks and initializes DynamoRIO */
void wizard(client_id_t id, int argc, const char *argv[]) {
    drreg_options_t ops = {sizeof(ops), 3, false};
    dr_set_client_name("Wizard",
                       "https://github.com/trailofbits/sienna-locomotive");

    if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS || !drwrap_init())
        DR_ASSERT(false);

    dr_register_exit_event(event_exit_trace);

    if (!drmgr_register_module_load_event(module_load_event) ||
        !drmgr_register_thread_init_event(event_thread_init) ||
        !drmgr_register_thread_exit_event(event_thread_exit))
    {
        DR_ASSERT(false);
    }

    dr_log(NULL, LOG_ALL, 1, "Client 'Wizard' initializing\n");
}

/* Parses options and calls wizard helper */
DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    std::string parse_err;
    int last_idx = 0;
    if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, &parse_err, &last_idx)) {
        dr_fprintf(STDERR, "Usage error: %s", parse_err.c_str());
        dr_abort();
    }

    wizard(id, argc, argv);
}
