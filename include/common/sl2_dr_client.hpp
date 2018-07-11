#ifndef SL2_DR_CLIENT_H
#define SL2_DR_CLIENT_H

#include <string>
#include "json.hpp"
using json = nlohmann::json;

extern "C" {
    #include "uuid.h"
}

// Macros for the function prototypes passed to pre- and post-function hooks.
#define SL2_PRE_PROTO void(__cdecl *)(void *, void **)
#define SL2_POST_PROTO void(__cdecl *)(void *, void *)

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
  UINT64 position;
  DWORD readSize;
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
