#include <stdio.h>
#include <stddef.h> /* for offsetof */
#include <map>
#include <set>

#include "common/sl2_dr_client.hpp"
#include "common/sl2_dr_client_options.hpp"

#include <iostream>
#include <codecvt>
#include <locale>

#include "vendor/picosha2.h"
using namespace std;

static SL2Client client;
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
Below we have a number of functions that instrument metadata retrieval for the individual functions we can hook.
*/

// TODO: hook functions that open the handles for these
//       so we can track the names of the resources getting read

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

/* prints information about the function call to stderr so the harness can ingest it */
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

    wstring_convert<std::codecvt_utf8<wchar_t>> utf8Converter;

    client_read_info *info   = ((client_read_info *)user_data);
    const char *func_name = function_to_string(info->function);

    json j;
    j["type"]               = "id";
    j["callCount"]          = client.incrementCallCountForFunction(info->function);
    j["retAddrCount"]       = client.incrementRetAddrCount(info->retAddrOffset);
    j["retAddrOffset"]      = (uint64_t) info->retAddrOffset;
    j["func_name"]          = func_name;



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

    if (info->function == Function::_read){
        #pragma warning(suppress: 4311 4302)
        nNumberOfBytesToRead = min(nNumberOfBytesToRead, (int) drwrap_get_retval(wrapcxt));
    }

    if ((long long) info->lpNumberOfBytesRead & 0xffffffff){
        nNumberOfBytesToRead = min(nNumberOfBytesToRead, (int) *(info->lpNumberOfBytesRead));
    }

    vector<unsigned char> x(lpBuffer, lpBuffer + min(nNumberOfBytesToRead, 64));
    j["buffer"] = x;

    SL2_LOG_JSONL(j);

    if (info->source) {
        dr_thread_free(drcontext, info->source, MAX_PATH + 1);
    }
    if (info->argHash) {
        dr_thread_free(drcontext, info->argHash, SL2_HASH_LEN + 1);
    }

    dr_thread_free(drcontext, info, sizeof(client_read_info));
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
        client.baseAddr = (size_t) mod->start;
    }

    json j;
    j["type"]               = "map";
    j["start"]              = (size_t) mod->start;
    j["end"]                = (size_t) mod->end;
    j["mod_name"]           = dr_module_preferred_name(mod);
    SL2_LOG_JSONL(j);

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

    sl2_pre_proto_map::iterator it;
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
                std::basic_ostringstream<char, std::char_traits<char>, sl2_dr_allocator<char>> s;
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

    dr_enable_console_printing();
    wizard(id, argc, argv);
}
