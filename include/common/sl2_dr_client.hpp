#ifndef SL2_DR_CLIENT_H
#define SL2_DR_CLIENT_H

// NOTE(ww): You might wonder why we don't include dr_api.h or other
// DynamoRIO headers in this file. The short reason is that the DynamoRIO
// headers rely on a bunch of macros that only get defined if you
// declare your (CMake) target as a DynamoRIO client. Since slcommon
// isn't a DynamoRIO client and defining all of those macros manually
// would be fragile, we leave it up to the individual clients
// to perform the includes.

#include <string>
#include "json.hpp"
using json = nlohmann::json;

extern "C" {
    #include "uuid.h"
}

// Used for debugging prints.
#define SL2_DEBUG(...) (dr_fprintf(STDERR, __VA_ARGS__))

// Macros for the function prototypes passed to pre- and post-function hooks.
#define SL2_PRE_PROTO void(__cdecl *)(void *, void **)
#define SL2_POST_PROTO void(__cdecl *)(void *, void *)

// Macros for quickly building a map of function names to function pre- and post-hooks.
// TODO(ww): There should really only be one of each of these (pre and post), but
// Microsoft's C preprocessor isn't C99 compliant and so makes things with __VA_ARGS__ hard.
#define SL2_PRE_HOOK1(map, func) (map[#func] = wrap_pre_##func)
#define SL2_PRE_HOOK2(map, func, hook_func) (map[#func] = wrap_pre_##hook_func)

#define SL2_POST_HOOK1(map, func) (map[#func] = wrap_post_##func)
#define SL2_POST_HOOK2(map, func, hook_func) (map[#func] = wrap_post_##hook_func)

// The set of currently supported functions.
enum class Function {
    ReadFile,
    recv,
    WinHttpReadData,
    InternetReadFile,
    WinHttpWebSocketReceive,
    RegQueryValueEx,
    ReadEventLog,
    fread,
    fread_s,
};

// The set of supported function targetting techniques.
enum {
    // Target a function by its index, e.g. the 5th `fread` call
    MATCH_INDEX = 1 << 0,

    // Target a function by its address, e.g. the `fread` at address 0x0000000a
    MATCH_RETN_ADDRESS = 1 << 1,

    // Target a function by a hash calculated from its arguments
    MATCH_ARG_HASH = 1 << 2,
};

// The struct filled with function information for hashing.
// See `MATCH_ARG_HASH`.
struct fileArgHash {
  WCHAR fileName[MAX_PATH + 1];
  size_t position;
  size_t readSize;
};

// The struct filled with targetting information for a function.
struct targetFunction {
  bool selected;
  UINT64 index;
  UINT64 mode;
  UINT64 retAddrOffset;
  std::string functionName;
  std::string argHash;
};

// Returns a C-string corresponding to the requested `function`.
__declspec(dllexport) char *get_function_name(Function function);

// Converts a JSON object into a `targetFunction`.
__declspec(dllexport) void from_json(const json& j, targetFunction& t);

#endif
