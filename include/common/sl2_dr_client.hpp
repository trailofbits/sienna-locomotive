#ifndef SL2_DR_CLIENT_H
#define SL2_DR_CLIENT_H

#include <string>
#include <fstream>
#include "vendor/json.hpp"
using json = nlohmann::json;
using namespace std;

extern "C" {
    #include "util.h"
    #include "uuid.h"
}

// Used for iterating over the function-module pair table.
#define SL2_FUNCMOD_TABLE_SIZE (sizeof(SL2_FUNCMOD_TABLE) / sizeof(SL2_FUNCMOD_TABLE[0]))

// Used for debugging prints.
#define SL2_DR_DEBUG(...) (dr_fprintf(STDERR, __VA_ARGS__))

// NOTE(ww): This loop is here because dr_fprintf has an internal buffer
// of 2048, and our JSON objects frequently exceed that. When that happens,
// dr_fprintf silently truncates them and confuses the harness with invalid JSON.
// We circumvent this by chunking the output.
#define SL2_LOG_JSONL(json) do {                                     \
    auto jsonl_str = json.dump();                                    \
    for (int i = 0; i < jsonl_str.length(); i += 1024) {             \
        dr_fprintf(STDERR, "%s", jsonl_str.substr(i, 1024).c_str()); \
    }                                                                \
    dr_fprintf(STDERR, "\n");                                        \
} while(0)

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
    _read,
};

// The set of supported function targetting techniques.
enum {
    // Target a function by its index, e.g. the 5th `fread` call
    MATCH_INDEX = 1 << 0,

    // Target a function by its address, e.g. the `fread` at address 0x0000000a
    MATCH_RETN_ADDRESS = 1 << 1,

    // Target a function by a hash calculated from its arguments
    MATCH_ARG_HASH = 1 << 2,

    // Target a function by contents of argument buffer
    MATCH_ARG_COMPARE = 1 << 3,

};

// The struct filled with function information for hashing.
// See `MATCH_ARG_HASH`.
struct fileArgHash {
  wchar_t fileName[MAX_PATH + 1];
  size_t position;
  size_t readSize;
};

// The struct filled with targetting information for a function.
typedef struct targetFunction {
    bool                    selected;
    uint64_t                index;
    uint64_t                mode;
    uint64_t                retAddrOffset;
    string                  functionName;
    string                  argHash;
    vector<uint8_t>         buffer;
} TargetFunction;

// Information for read in fuzzer and tracer clients
struct client_read_info {
    uint64_t    position;
    uint64_t    retAddrOffset;
    Function    function;
    HANDLE      hFile;
    DWORD       *lpNumberOfBytesRead;
    void        *lpBuffer;
    char        *argHash;
    size_t      nNumberOfBytesToRead;
};

// The struct filled with exception information for registering
// within a minidump.
struct sl2_exception_ctx {
    DWORD thread_id;
    EXCEPTION_RECORD record;
    CONTEXT thread_ctx;
};

// Represents a tuple of a function and its expected module.
struct sl2_funcmod
{
    char *func;
    char *mod;
};

// Declared in sl2_dr_client.cpp; contains pairs of functions and their expected modules.
extern sl2_funcmod SL2_FUNCMOD_TABLE[];

///////////////////////////////////////////////////////////////////////////////////////////////////
// SL2Client
///////////////////////////////////////////////////////////////////////////////////////////////////
class SL2Client {

private:


public:
    SL2Client();

    ////////////////////////////////////////////////////////////////////////////////////////////
    // Variables
    // TODO(ww): Subsume sl2_conn under SL2Client.
    map<Function, uint64_t>     call_counts;
    json                        parsedJson;

    ////////////////////////////////////////////////////////////////////////////////////////////
    // Methods
    bool        isFunctionTargeted(Function function,  client_read_info* info);
    bool        areTargetsArenaCompatible();
    void        generateArenaId(wchar_t *id);
    bool        loadJson(string json);
    uint64_t    incrementCallCountForFunction(Function function);

};

// Converts a JSON object into a `targetFunction`.
SL2_EXPORT
void from_json(const json& j, targetFunction& t);

// Returns a C-string corresponding to the requested `function`.
SL2_EXPORT
const char *function_to_string(Function function);

// Returns a C-string corresponding to the given `exception_code`.
SL2_EXPORT
const char *exception_to_string(DWORD exception_code);

// Returns a boolean, indicating whether or not the given function is in
// the module we expected (for hooking).
// Returns false if the module isn't the one we expect *or* if the function isn't
// one we care about.
SL2_EXPORT
bool function_is_in_expected_module(const char *func, const char *mod);

#endif
