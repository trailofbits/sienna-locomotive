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

#include "vendor/picosha2.h"
using namespace std;

#include "common/sl2_dr_client.hpp"

// function metadata structure
struct wizard_read_info {
    void *lpBuffer;
    size_t nNumberOfBytesToRead;
    Function function;
    wchar_t *source;
    size_t position;
    size_t retAddrOffset;
    // TODO(ww): Make this a wchar_t * for consistency.
    char *argHash;
};

static size_t baseAddr;
static std::map<Function, UINT64> call_counts;

/* Run whenever a thread inits/exits */
static void
on_thread_init(void *drcontext)
{
    SL2_DR_DEBUG("wizard#on_thread_init\n");
}

static void
on_thread_exit(void *drcontext)
{
    SL2_DR_DEBUG("wizard#on_thread_exit\n");
}

/* Clean up after the target binary exits */
static void
on_dr_exit(void)
{
    SL2_DR_DEBUG("wizard#on_dr_exit\n");

    if (!drmgr_unregister_thread_init_event(on_thread_init) ||
        !drmgr_unregister_thread_exit_event(on_thread_exit) ||
        drreg_exit() != DRREG_SUCCESS)
    {
        DR_ASSERT(false);
    }

    drmgr_exit();
}

/*
Below we have a number of functions that instrument metadata retreival for the individual functions we can hook.
*/

// TODO: hook functions that open the handles for these
//       so we can track the names of the resources geing read

static void
wrap_pre_ReadEventLog(void *wrapcxt, OUT void **user_data)
{
    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(wizard_read_info));
    wizard_read_info *info = (wizard_read_info *) *user_data;

    HANDLE hEventLog                 = (HANDLE) drwrap_get_arg(wrapcxt, 0);
    #pragma warning(suppress: 4311 4302)
    DWORD  dwReadFlags               = (DWORD) drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    DWORD  dwRecordOffset            = (DWORD) drwrap_get_arg(wrapcxt, 2);
    void *lpBuffer                   = drwrap_get_arg(wrapcxt, 3);
    #pragma warning(suppress: 4311 4302)
    size_t  nNumberOfBytesToRead     = (DWORD) drwrap_get_arg(wrapcxt, 4);
    DWORD  *pnBytesRead              = (DWORD *) drwrap_get_arg(wrapcxt, 5);
    DWORD  *pnMinNumberOfBytesNeeded = (DWORD *) drwrap_get_arg(wrapcxt, 6);

    info->lpBuffer             = lpBuffer;
    info->nNumberOfBytesToRead = nNumberOfBytesToRead;
    info->function             = Function::ReadEventLog;
    info->source               = NULL;
    info->position             = NULL;
    info->retAddrOffset        = (size_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}


static void
wrap_pre_RegQueryValueEx(void *wrapcxt, OUT void **user_data)
{
    HKEY hKey         = (HKEY) drwrap_get_arg(wrapcxt, 0);
    char *lpValueName = (char *) drwrap_get_arg(wrapcxt, 1);
    DWORD *lpReserved = (DWORD *) drwrap_get_arg(wrapcxt, 2);
    DWORD *lpType     = (DWORD *) drwrap_get_arg(wrapcxt, 3);
    BYTE *lpData      = (BYTE *) drwrap_get_arg(wrapcxt, 4);
    DWORD *lpcbData   = (DWORD *) drwrap_get_arg(wrapcxt, 5);

    // get registry key path (maybe hook open key?)

    if (lpData != NULL && lpcbData != NULL) {
        *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(wizard_read_info));
        wizard_read_info *info = (wizard_read_info *) *user_data;

        info->lpBuffer             = lpData;
        info->nNumberOfBytesToRead = *lpcbData;
        info->function             = Function::RegQueryValueEx;
        info->source               = NULL;
        info->position             = NULL;
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
    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(wizard_read_info));
    wizard_read_info *info = (wizard_read_info *) *user_data;

    HINTERNET hRequest                          = (HINTERNET) drwrap_get_arg(wrapcxt, 0);
    void *pvBuffer                              = drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    DWORD dwBufferLength                        = (DWORD) drwrap_get_arg(wrapcxt, 2);
    DWORD *pdwBytesRead                         = (DWORD *) drwrap_get_arg(wrapcxt, 3);
    #pragma warning(suppress: 4311 4302)
    WINHTTP_WEB_SOCKET_BUFFER_TYPE peBufferType = (WINHTTP_WEB_SOCKET_BUFFER_TYPE) (int) drwrap_get_arg(wrapcxt, 3);

    // get url
    // InternetQueryOption

    info->lpBuffer             = pvBuffer;
    info->nNumberOfBytesToRead = dwBufferLength;
    info->function             = Function::WinHttpWebSocketReceive;
    info->source               = NULL;
    info->position             = NULL;
    info->retAddrOffset        = (size_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}

static void
wrap_pre_InternetReadFile(void *wrapcxt, OUT void **user_data)
{
    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(wizard_read_info));
    wizard_read_info *info = (wizard_read_info *) *user_data;

    HINTERNET hFile            = (HINTERNET) drwrap_get_arg(wrapcxt, 0);
    void *lpBuffer             = drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    DWORD nNumberOfBytesToRead = (DWORD) drwrap_get_arg(wrapcxt, 2);
    DWORD *lpNumberOfBytesRead = (DWORD *) drwrap_get_arg(wrapcxt, 3);

    // get url
    // InternetQueryOption

    info->lpBuffer             = lpBuffer;
    info->nNumberOfBytesToRead = nNumberOfBytesToRead;
    info->function             = Function::InternetReadFile;
    info->source               = NULL;
    info->position             = NULL;
    info->retAddrOffset        = (size_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}

static void
wrap_pre_WinHttpReadData(void *wrapcxt, OUT void **user_data)
{
    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(wizard_read_info));
    wizard_read_info *info = (wizard_read_info *) *user_data;

    HINTERNET hRequest         = (HINTERNET)drwrap_get_arg(wrapcxt, 0);
    void *lpBuffer             = drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    DWORD nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 2);
    DWORD *lpNumberOfBytesRead = (DWORD*)drwrap_get_arg(wrapcxt, 3);

    // get url
    // InternetQueryOption

    info->lpBuffer             = lpBuffer;
    info->nNumberOfBytesToRead = nNumberOfBytesToRead;
    info->function             = Function::WinHttpReadData;
    info->source               = NULL;
    info->position             = NULL;
    info->retAddrOffset        = (size_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}

static void
wrap_pre_recv(void *wrapcxt, OUT void **user_data)
{
    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(wizard_read_info));
    wizard_read_info *info = (wizard_read_info *) *user_data;

    SOCKET s  = (SOCKET)drwrap_get_arg(wrapcxt, 0);
    char *buf = (char *)drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    int len   = (int)drwrap_get_arg(wrapcxt, 2);
    #pragma warning(suppress: 4311 4302)
    int flags = (int)drwrap_get_arg(wrapcxt, 3);

    // get ip address
    // getpeername

    info->lpBuffer             = buf;
    info->nNumberOfBytesToRead = len;
    info->function             = Function::recv;
    info->source               = NULL;
    info->position             = NULL;
    info->retAddrOffset        = (size_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;

    // get peer name doesn't work
    // https://github.com/DynamoRIO/dynamorio/issues/1883

    // struct sockaddr_in peer;
    // int peer_len = sizeof(peer);
    // getpeername(s, (sockaddr *)&peer, &peer_len);
    // dr_printf("Peer's IP address is: %s\n", inet_ntoa(peer.sin_addr));
    // dr_printf("Peer's port is: %d\n", (int) ntohs(peer.sin_port));
}

static void
wrap_pre_ReadFile(void *wrapcxt, OUT void **user_data)
{
    HANDLE hFile               = drwrap_get_arg(wrapcxt, 0);
    void *lpBuffer             = drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    DWORD nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 2);
    DWORD *lpNumberOfBytesRead = (DWORD *)drwrap_get_arg(wrapcxt, 3);

    LARGE_INTEGER offset = {0};
    LARGE_INTEGER position = {0};
    SetFilePointerEx(hFile, offset, &position, FILE_CURRENT);

    fileArgHash fStruct = {0};

    GetFinalPathNameByHandle(hFile, fStruct.fileName, MAX_PATH, FILE_NAME_NORMALIZED);
    fStruct.position = position.QuadPart;
    fStruct.readSize = nNumberOfBytesToRead;

    std::vector<unsigned char> blob_vec((unsigned char *) &fStruct,
        ((unsigned char *) &fStruct) + sizeof(fileArgHash));
    std::string hash_str;
    picosha2::hash256_hex_string(blob_vec, hash_str);

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(wizard_read_info));
    wizard_read_info *info = (wizard_read_info *) *user_data;

    info->lpBuffer             = lpBuffer;
    info->nNumberOfBytesToRead = nNumberOfBytesToRead;
    info->function             = Function::ReadFile;
    info->retAddrOffset        = (size_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->position             = fStruct.position;

    info->source = (wchar_t *) dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(fStruct.fileName));
    memcpy(info->source, fStruct.fileName, sizeof(fStruct.fileName));

    info->argHash = (char *) dr_thread_alloc(drwrap_get_drcontext(wrapcxt), SL2_HASH_LEN + 1);
    info->argHash[SL2_HASH_LEN] = 0;
    memcpy(info->argHash, hash_str.c_str(), SL2_HASH_LEN);
}

static void
wrap_pre_fread(void *wrapcxt, OUT void **user_data)
{
    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(wizard_read_info));
    wizard_read_info *info = (wizard_read_info *) *user_data;

    void *buffer = (void *)drwrap_get_arg(wrapcxt, 0);
    size_t size  = (size_t)drwrap_get_arg(wrapcxt, 1);
    size_t count = (size_t)drwrap_get_arg(wrapcxt, 2);

    info->lpBuffer             = buffer;
    info->nNumberOfBytesToRead = size * count;
    info->function             = Function::fread;
    info->source               = NULL;
    info->position             = NULL;
    info->retAddrOffset        = (size_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}

static void
wrap_pre_fread_s(void *wrapcxt, OUT void **user_data)
{
    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(wizard_read_info));
    wizard_read_info *info = (wizard_read_info *) *user_data;

    void *buffer = (void *)drwrap_get_arg(wrapcxt, 0);
    size_t size  = (size_t)drwrap_get_arg(wrapcxt, 2);
    size_t count = (size_t)drwrap_get_arg(wrapcxt, 3);

    info->lpBuffer             = buffer;
    info->nNumberOfBytesToRead = size * count;
    info->function             = Function::fread_s;
    info->source               = NULL;
    info->position             = NULL;
    info->retAddrOffset        = (size_t) drwrap_get_retaddr(wrapcxt) - baseAddr;
    info->argHash              = NULL;
}

/* prints information about the function call to stderr so the harness can ingest it */
static void
wrap_post_Generic(void *wrapcxt, void *user_data)
{
    if (user_data == NULL) {
        return;
    }

    wstring_convert<std::codecvt_utf8<wchar_t>> utf8Converter;

    wizard_read_info *info   = ((wizard_read_info *)user_data);
    const char *func_name = function_to_string(info->function);

    json j;
    j["type"]               = "id";
    j["callCount"]          = call_counts[info->function];
    j["retAddrOffset"]      = (UINT64) info->retAddrOffset;
    j["func_name"]          = func_name;

    call_counts[info->function]++;

    if(info->source != NULL) {
        wstring wsource =  wstring(info->source);
        j["source"]  = utf8Converter.to_bytes(wsource);

        size_t end   = info->position + info->nNumberOfBytesToRead;
        j["start"]   = info->position;
        j["end"]     = end;
    }

    if (info->argHash != NULL) {
        j["argHash"] = info->argHash;
    }

    char *lpBuffer = (char *) info->lpBuffer;
    size_t nNumberOfBytesToRead = info->nNumberOfBytesToRead;

    vector<unsigned char> x(lpBuffer, lpBuffer + min(nNumberOfBytesToRead, 64));
    j["buffer"] = x;

    SL2_LOG_JSONL(j);

    if (info->source) {
        dr_thread_free(drwrap_get_drcontext(wrapcxt), info->source, MAX_PATH + 1);
    }
    if (info->argHash) {
        dr_thread_free(drwrap_get_drcontext(wrapcxt), info->argHash, SL2_HASH_LEN + 1);
    }

    dr_thread_free(drwrap_get_drcontext(wrapcxt), info, sizeof(wizard_read_info));
}

/* Runs every time we load a new module. Wraps functions we can target. See fuzzer.cpp for a more-detailed version */
static void
on_module_load(void *drcontext, const module_data_t *mod, bool loaded)
{
    /*
        ReadFile is hooked twice, in kernel32 and kernelbase.
        kernelbase is forwarded to kernel32, so if we want to filter
            to only one hook make sure we hook kernel32.
    */

    if (!strcmp(dr_get_application_name(), dr_module_preferred_name(mod))){
      baseAddr = (size_t) mod->start;
    }

    json j;
    j["type"]               = "map";
    j["start"]              = (size_t) mod->start;
    j["end"]                = (size_t) mod->end;
    j["mod_name"]           = dr_module_preferred_name(mod);
    SL2_LOG_JSONL(j);

    std::map<char *, SL2_PRE_PROTO> toHookPre;
    SL2_PRE_HOOK1(toHookPre, ReadFile);
    SL2_PRE_HOOK1(toHookPre, InternetReadFile);
    SL2_PRE_HOOK2(toHookPre, ReadEventLogA, ReadEventLog);
    SL2_PRE_HOOK2(toHookPre, ReadEventLogW, ReadEventLog);
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
    SL2_POST_HOOK2(toHookPost, ReadEventLogA, Generic);
    SL2_POST_HOOK2(toHookPost, ReadEventLogW, Generic);
    SL2_POST_HOOK2(toHookPost, RegQueryValueExW, Generic);
    SL2_POST_HOOK2(toHookPost, RegQueryValueExA, Generic);
    SL2_POST_HOOK2(toHookPost, WinHttpWebSocketReceive, Generic);
    SL2_POST_HOOK2(toHookPost, WinHttpReadData, Generic);
    SL2_POST_HOOK2(toHookPost, recv, Generic);
    SL2_POST_HOOK2(toHookPost, fread_s, Generic);
    SL2_POST_HOOK2(toHookPost, fread, Generic);

    std::map<char *, SL2_PRE_PROTO>::iterator it;
    for (it = toHookPre.begin(); it != toHookPre.end(); it++) {
        char *functionName = it->first;

        void(__cdecl *hookFunctionPre)(void *, void **);
        hookFunctionPre = it->second;
        void(__cdecl *hookFunctionPost)(void *, void *);
        hookFunctionPost = NULL;

        // TODO(ww): Why do we do this, instead of just assigning above?
        if (toHookPost.find(functionName) != toHookPost.end()) {
            hookFunctionPost = toHookPost[functionName];
        }

        app_pc towrap = (app_pc) dr_get_proc_address(mod->handle, functionName);
        const char *mod_name = dr_module_preferred_name(mod);

        if (!function_is_in_expected_module(functionName, mod_name)) {
            continue;
        }

        if (towrap != NULL) {
            dr_flush_region(towrap, 0x1000);
            bool ok = drwrap_wrap(towrap, hookFunctionPre, hookFunctionPost);
            json j;

            if (!ok) {
                j["type"] = "error";
                ostringstream s;
                s << "FAILED to wrap " << functionName <<  " @ " << towrap << " already wrapped?";
                j["msg"] = s.str();
                SL2_LOG_JSONL(j);
            }
        }
    }
}

/* registers event callbacks and initializes DynamoRIO */
void wizard(client_id_t id, int argc, const char *argv[])
{
    drreg_options_t ops = {sizeof(ops), 3, false};
    dr_set_client_name("Wizard",
                       "https://github.com/trailofbits/sienna-locomotive");

    if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS || !drwrap_init())
        DR_ASSERT(false);

    dr_register_exit_event(on_dr_exit);

    if (!drmgr_register_module_load_event(on_module_load) ||
        !drmgr_register_thread_init_event(on_thread_init) ||
        !drmgr_register_thread_exit_event(on_thread_exit))
    {
        DR_ASSERT(false);
    }

    dr_log(NULL, DR_LOG_ALL, 1, "Client 'Wizard' initializing\n");
}

/* Parses options and calls wizard helper */
DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    std::string parse_err;
    int last_idx = 0;
    if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, &parse_err, &last_idx)) {
        SL2_DR_DEBUG("wizard#main: usage error: %s", parse_err.c_str());
        dr_abort();
    }

    wizard(id, argc, argv);
}
