#include "vendor/picosha2.h"

#include "common/sl2_dr_client.hpp"
#include "dr_api.h"

using namespace std;

///////////////////////////////////////////////////////////////////////////////////////////////////
// SL2Client
//
// Intended to be for common functionality for DynamoRio clients. This should be moved inside
// the DR build process eventually and be the superclass of Fuzzer and Tracer subclasses.
/////////////////////////////////////////////////////////////////////////////////////////////////
SL2Client::SL2Client() {

}


///////////////////////////////////////////////////////////////////////////////////////////////////
// isFunctionTargeted()
//
// Returns true if the current function should be targeted.
bool SL2Client::
isFunctionTargeted(Function function, client_read_info* info) {

    std::string strFunctionName(get_function_name(function));

    for (targetFunction t : parsedJson){
        if (t.selected && t.functionName == strFunctionName) {
            if (t.mode & MATCH_INDEX && call_counts[function] == t.index) {
                return true;
            }
            else if (t.mode & MATCH_RETN_ADDRESS && t.retAddrOffset == info->retAddrOffset) {
                return true;
            }
            else if (t.mode & MATCH_ARG_HASH && !strcmp(t.argHash.c_str(), info->argHash)) {
                return true;
            }
            else if( t.mode & MATCH_ARG_COMPARE ) {
                size_t  minimum = 16;
                int     comp;

                minimum = min( minimum, t.buffer.size() );
                if( info->lpNumberOfBytesRead ) {
                    minimum = min( minimum, *info->lpNumberOfBytesRead) ;
                }

                uint8_t* buf = (uint8_t*)info->lpBuffer;
                comp = memcmp( &t.buffer[0], buf, minimum );
                if(comp==0) {
                    return true;
                }
            }
        }
    }
    return false;
}

// Returns true if the function targets identified by the client can be used with
// a coverage arena.
//
// NOTE(ww): Eventually, this should always be true. However, for the time being,
// we're using the "index" targetting mode to create a stable identifier for a
// coverage arena. As such, only function targets that were created with that
// mode are currently arena-compatible.
bool SL2Client::
areTargetsArenaCompatible()
{
    for (targetFunction t : parsedJson) {
        if (t.mode != MATCH_INDEX) {
            return false;
        }
    }

    return true;
}

// Generates an arena ID based upon the indices and names of the client's targeted functions.
// `id` *must* be large enough to hold `SL2_HASH_LEN + 1` widechars.
void SL2Client::
generateArenaId(wchar_t *id)
{
    picosha2::hash256_one_by_one hasher;

    for (targetFunction t : parsedJson) {
        std::string index = std::to_string(t.index);

        hasher.process(index.begin(), index.end());
        hasher.process(t.functionName.begin(), t.functionName.end());
    }

    hasher.finish();

    // NOTE(ww): This cheeses C++ into using a stack-allocated string.
    // We do this because allocating a std::string within picosha2 freaks
    // DynamoRIO out. I'm not proud of it.
    char cheese[SL2_HASH_LEN + 1] = {0};
    std::string stdcheese(cheese);

    picosha2::get_hash_hex_string(hasher, stdcheese);
    mbstowcs_s(NULL, id, SL2_HASH_LEN + 1, stdcheese.c_str(), SL2_HASH_LEN);
    id[SL2_HASH_LEN] = '\0';
}

// TODO(ww): Use this instead of duplicating code across all three clients.
// bool SL2Client::functionIsInUnexpectedModule(char *function, char *module)
// {
//     #define FUNC_AND_MOD(exp_f, exp_m) ((STREQ(exp_f, function) && STREQI(exp_m, module)))

//     return (FUNC_AND_MOD("ReadFile", "KERNELBASE.DLL")
//             || FUNC_AND_MOD("RegQueryValueExA", "KERNELBASE.DLL")
//             || FUNC_AND_MOD("RegQueryValueExW", "KERNELBASE.DLL")
//             || FUNC_AND_MOD("fread", "UCRTBASE.DLL")
//             || FUNC_AND_MOD("fread_s", "UCRTBASE.DLL"))

//     #undef FUNC_AND_MOD
// }


///////////////////////////////////////////////////////////////////////////////////////////////////
// incrementCallCountForFunction()
//
// Increments the total number of call counts for this function
uint64_t    SL2Client::
incrementCallCountForFunction(Function function) {
    return call_counts[function]++;
}


///////////////////////////////////////////////////////////////////////////////////////////////////
// loadJson()
//
// Loads json blob into client
// TODO(ww): Rename to loadTargets, to reflect the fact that we're not using JSON anymore?
bool SL2Client::
loadJson(string path)
{
    file_t targets = dr_open_file(path.c_str(), DR_FILE_READ);
    size_t targets_size;
    size_t txsize;

    dr_file_size(targets, &targets_size);
    uint8_t *buffer = (uint8_t *) dr_global_alloc(targets_size);

    txsize = dr_read_file(targets, buffer, targets_size);
    dr_close_file(targets);

    if (txsize != targets_size) {
        dr_global_free(buffer, targets_size);
        return false;
    }

    std::vector<std::uint8_t> msg(buffer, buffer + targets_size);

    parsedJson = json::from_msgpack(msg);

    dr_global_free(buffer, targets_size);

    return parsedJson.is_array();
}


__declspec(dllexport) char *get_function_name(Function function)
{
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
        case Function::fread:
            return "fread";
        case Function::fread_s:
            return "fread_s";
    }

    return "unknown";
}

// TODO(ww): Document the fallback values here.
__declspec(dllexport) void from_json(const json& j, targetFunction& t)
{
    t.selected      = j.value("selected", false);
    t.index         = j.value("callCount", -1);
    t.mode          = j.value("mode", MATCH_INDEX);
    t.retAddrOffset = j.value("retAddrOffset", -1);
    t.functionName  = j.value("func_name", "");
    t.argHash       = j.value("argHash", "");
    t.buffer        = j["buffer"].get<vector<uint8_t>>();
}
