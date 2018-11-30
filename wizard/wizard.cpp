#include <map>
#include <iostream>
#include <codecvt>

#include "common/sl2_dr_client.hpp"
#include "common/sl2_dr_client_options.hpp"

#include "vendor/picosha2.h"
using namespace std;

/*! Creates a client for the wizard to use (not inherited) */
static SL2Client client;

/** Print a debug message when a new thread starts */
static void on_thread_init(void *drcontext) {
  SL2_DR_DEBUG("wizard#on_thread_init\n");
}

/** Print a debug message when a thread exits */
static void on_thread_exit(void *drcontext) {
  SL2_DR_DEBUG("wizard#on_thread_exit\n");
}

/** We shouldn't need to handle exceptions in the wizard.
 *  Just records the exception and exits.
 */
static bool on_exception(void *drcontext, dr_exception_t *excpt) {
  SL2_DR_DEBUG("The target application crashed under the wizard!\n");

  json j;

  j["type"] = "error";
  j["exception"] = client.exception_to_string(excpt->record->ExceptionCode);

  SL2_LOG_JSONL(j);

  dr_exit_process(1);
  return true;
}

/** Clean up after the target binary exits */
static void on_dr_exit(void) {
  SL2_DR_DEBUG("wizard#on_dr_exit\n");

  drwrap_exit();

  if (!drmgr_unregister_thread_init_event(on_thread_init) ||
      !drmgr_unregister_thread_exit_event(on_thread_exit) || drreg_exit() != DRREG_SUCCESS) {
    DR_ASSERT(false);
  }

  drmgr_exit();
}

/*
Below we have a number of functions that instrument metadata retrieval for the individual functions
we can hook.
*/

// TODO: hook functions that open the handles for these
//       so we can track the names of the resources getting read

/** Transparent wrapper around SL2Client.wrap_pre_ReadEventLog */
static void wrap_pre_ReadEventLog(void *wrapcxt, OUT void **user_data) {
  client.wrap_pre_ReadEventLog(wrapcxt, user_data);
}

/** Transparent wrapper around SL2Client.wrap_pre_RegQueryValueEx */
static void wrap_pre_RegQueryValueEx(void *wrapcxt, OUT void **user_data) {
  client.wrap_pre_RegQueryValueEx(wrapcxt, user_data);
}

/** Transparent wrapper around SL2Client.wrap_pre_WinHttpWebSocketReceive */
static void wrap_pre_WinHttpWebSocketReceive(void *wrapcxt, OUT void **user_data) {
  client.wrap_pre_WinHttpWebSocketReceive(wrapcxt, user_data);
}

/** Transparent wrapper around SL2Client.wrap_pre_InternetReadFile */
static void wrap_pre_InternetReadFile(void *wrapcxt, OUT void **user_data) {
  client.wrap_pre_InternetReadFile(wrapcxt, user_data);
}

/** Transparent wrapper around SL2Client.wrap_pre_WinHttpReadData */
static void wrap_pre_WinHttpReadData(void *wrapcxt, OUT void **user_data) {
  client.wrap_pre_WinHttpReadData(wrapcxt, user_data);
}

/** Transparent wrapper around SL2Client.wrap_pre_recv */
static void wrap_pre_recv(void *wrapcxt, OUT void **user_data) {
  client.wrap_pre_recv(wrapcxt, user_data);
}

/** Transparent wrapper around SL2Client.wrap_pre_ReadFile */
static void wrap_pre_ReadFile(void *wrapcxt, OUT void **user_data) {
  client.wrap_pre_ReadFile(wrapcxt, user_data);
}

/** Transparent wrapper around SL2Client.wrap_pre_fread_s */
static void wrap_pre_fread_s(void *wrapcxt, OUT void **user_data) {
  client.wrap_pre_fread_s(wrapcxt, user_data);
}

/** Transparent wrapper around SL2Client.wrap_pre_fread */
static void wrap_pre_fread(void *wrapcxt, OUT void **user_data) {
  client.wrap_pre_fread(wrapcxt, user_data);
}

/** Transparent wrapper around SL2Client.wrap_pre__read */
static void wrap_pre__read(void *wrapcxt, OUT void **user_data) {
  client.wrap_pre__read(wrapcxt, user_data);
}

/** Transparent wrapper around SL2Client.wrap_pre_MapViewOfFile */
static void wrap_pre_MapViewOfFile(void *wrapcxt, OUT void **user_data) {
  client.wrap_pre_MapViewOfFile(wrapcxt, user_data);
}

/**
 * Prints information about the function call caught by the pre-wrapper to stderr so the harness can
 * ingest it
 * @param wrapcxt DynamoRIO Wrap context. Only used as an argument to DynamoRIO's helper methods
 * @param user_data struct with metadata about the function call
 */
static void wrap_post_Generic(void *wrapcxt, void *user_data) {
  void *drcontext = NULL;

  if (!client.is_sane_post_hook(wrapcxt, user_data, &drcontext)) {
    // TODO(ww): Use a goto here and fix the C++ initialization errors.
    return;
  }

  wstring_convert<std::codecvt_utf8<wchar_t>> utf8Converter;

  client_read_info *info = (client_read_info *)user_data;
  const char *func_name = client.function_to_string(info->function);

  json j;
  j["type"] = "id";
  j["callCount"] = client.increment_call_count(info->function);
  j["retAddrCount"] = client.increment_retaddr_count(info->retAddrOffset);
  j["retAddrOffset"] = (uint64_t)info->retAddrOffset;
  j["func_name"] = func_name;

  if (info->source != NULL) {
    wstring wsource = wstring(info->source);
    j["source"] = utf8Converter.to_bytes(wsource);

    size_t end = info->position + info->nNumberOfBytesToRead;
    j["start"] = info->position;
    j["end"] = end;
  }

  if (info->argHash != NULL) {
    j["argHash"] = info->argHash;
  }

  if (info->function == Function::_read) {
#pragma warning(suppress : 4311 4302)
    info->nNumberOfBytesToRead = min(info->nNumberOfBytesToRead, (int)drwrap_get_retval(wrapcxt));
  }

  if ((long long)info->lpNumberOfBytesRead & 0xffffffff) {
    info->nNumberOfBytesToRead = min(info->nNumberOfBytesToRead, (int)*(info->lpNumberOfBytesRead));
  }

  vector<unsigned char> x((char *)info->lpBuffer,
                          ((char *)info->lpBuffer) + min(info->nNumberOfBytesToRead, 64));
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

/**
 * MapViewOfFile can't use the Generic post-hook, as we need the address of the mapped view that it
 * returns.
 */
static void wrap_post_MapViewOfFile(void *wrapcxt, void *user_data) {
  void *drcontext = NULL;
  bool interesting_call = true;

  if (!client.is_sane_post_hook(wrapcxt, user_data, &drcontext)) {
    // TODO(ww): Use a goto here and fix the C++ initialization errors.
    return;
  }

  client_read_info *info = ((client_read_info *)user_data);
  const char *func_name = client.function_to_string(info->function);

  info->lpBuffer = drwrap_get_retval(wrapcxt);

  wstring_convert<std::codecvt_utf8<wchar_t>> utf8Converter;

  json j;
  j["type"] = "id";
  j["callCount"] = client.increment_call_count(info->function);
  j["retAddrCount"] = client.increment_retaddr_count(info->retAddrOffset);
  j["retAddrOffset"] = (uint64_t)info->retAddrOffset;
  j["func_name"] = func_name;

  hash_context hash_ctx = {0};

  if (!GetMappedFileName(GetCurrentProcess(), info->lpBuffer, hash_ctx.fileName, MAX_PATH)) {
    // NOTE(ww): This can happen when a memory-mapped object doesn't have a real file
    // backing it, e.g. when the mapping is of the page file or some other
    // kernel-managed resource. When that happens, we assume it's not something
    // that the user wants to target.
    SL2_DR_DEBUG("GetMappedFileName failed (GLE=%d)\n", GetLastError());
    SL2_DR_DEBUG("Assuming the call isn't interesting!\n");
    interesting_call = false;
  }

  if (interesting_call) {
    MEMORY_BASIC_INFORMATION memory_info = {0};

    // NOTE(ww): If nNumberOfBytesToRead=0, then the entire file is being mapped.
    // Get the real size by querying the base address with VirtualQuery.
    if (!info->nNumberOfBytesToRead) {
      dr_virtual_query((byte *)info->lpBuffer, &memory_info, sizeof(memory_info));

      info->nNumberOfBytesToRead = memory_info.RegionSize;
    }

    hash_ctx.readSize = info->nNumberOfBytesToRead;

    j["source"] = utf8Converter.to_bytes(wstring(hash_ctx.fileName));

    size_t end = info->position + info->nNumberOfBytesToRead;
    j["start"] = info->position;
    j["end"] = end;

    client.hash_args(info->argHash, &hash_ctx);

    j["argHash"] = info->argHash;

    vector<unsigned char> x((char *)info->lpBuffer,
                            ((char *)info->lpBuffer) + min(info->nNumberOfBytesToRead, 64));
    j["buffer"] = x;

    SL2_LOG_JSONL(j);
  }

  dr_thread_free(drcontext, info->argHash, SL2_HASH_LEN + 1);
  dr_thread_free(drcontext, info, sizeof(client_read_info));
}

/**
 * Called every time a module loads. Wraps target-able functions with pre and post callbacks
 * if they're in the right module.
 * @param drcontext - DynamoRIO context
 * @param mod Module Data
 * @param loaded Unused
 */
static void on_module_load(void *drcontext, const module_data_t *mod, bool loaded) {
  if (!strcmp(dr_get_application_name(), dr_module_preferred_name(mod))) {
    client.baseAddr = (size_t)mod->start;
  }

  json j;
  j["type"] = "map";
  j["start"] = (size_t)mod->start;
  j["end"] = (size_t)mod->end;
  j["mod_name"] = dr_module_preferred_name(mod);
  SL2_LOG_JSONL(j);

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

  void(__cdecl * pre_hook)(void *, void **);
  void(__cdecl * post_hook)(void *, void *);

  sl2_pre_proto_map::iterator it;
  for (it = pre_hooks.begin(); it != pre_hooks.end(); it++) {
    char *function_name = it->first;

    pre_hook = it->second;
    post_hook = post_hooks[function_name];

    app_pc towrap = (app_pc)dr_get_proc_address(mod->handle, function_name);
    const char *mod_name = dr_module_preferred_name(mod);

    if (!client.function_is_in_expected_module(function_name, mod_name)) {
      continue;
    }

    if (towrap != NULL) {
      dr_flush_region(towrap, 0x1000);
      bool ok = drwrap_wrap(towrap, pre_hook, post_hook);
      json j;

      if (!ok) {
        j["type"] = "error";
        std::basic_ostringstream<char, std::char_traits<char>, sl2_dr_allocator<char>> s;
        s << "FAILED to wrap " << function_name << " @ " << towrap << " already wrapped?";
        j["msg"] = s.str();
        SL2_LOG_JSONL(j);
      }
    }
  }
}

/*! Parses options and calls wizard helper */
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
  std::string parse_err;
  int last_idx = 0;

  if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, &parse_err, &last_idx)) {
    SL2_DR_DEBUG("wizard#main: usage error: %s", parse_err.c_str());
    dr_abort();
  }

  dr_enable_console_printing();

  drreg_options_t ops = {sizeof(ops), 3, false};
  dr_set_client_name("Wizard", "https://github.com/trailofbits/sienna-locomotive");

  if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS || !drwrap_init()) {
    DR_ASSERT(false);
  }

  dr_register_exit_event(on_dr_exit);

  if (!drmgr_register_module_load_event(on_module_load) ||
      !drmgr_register_thread_init_event(on_thread_init) ||
      !drmgr_register_thread_exit_event(on_thread_exit) ||
      !drmgr_register_exception_event(on_exception)) {
    DR_ASSERT(false);
  }

  dr_log(NULL, DR_LOG_ALL, 1, "Client 'Wizard' initializing\n");
}
