#include "vendor/picosha2.h"

#include "common/sl2_dr_client.hpp"
#include "dr_api.h"

using namespace std;

// NOTE(ww): As of Windows 10, both KERNEL32.dll and ADVAPI32.dll
// get forwarded to KERNELBASE.DLL, apparently.
// TODO(ww): Since we iterate over these, order them by likelihood of occurrence?
sl2_funcmod SL2_FUNCMOD_TABLE[] = {
    {"ReadFile", "KERNELBASE.DLL"},
    {"recv", "WS2_32.DLL"},                     // TODO(ww): Is this right?
    {"WinHttpReadData", "WINHTTP.DLL"},         // TODO(ww): Is this right?
    {"InternetReadFile", "WININET.DLL"},        // TODO(ww): Is this right?
    {"WinHttpWebSocketReceive", "WINHTTP.DLL"}, // TODO(ww): Is this right?
    {"RegQueryValueExA", "KERNELBASE.DLL"},
    {"RegQueryValueExW", "KERNELBASE.DLL"},
    {"ReadEventLogA", "KERNELBASE.DLL"},
    {"ReadEventLogW", "KERNELBASE.DLL"},
    {"fread", "UCRTBASE.DLL"},
    {"fread", "UCRTBASED.DLL"},
    {"fread_s", "UCRTBASE.DLL"},
    {"fread_s", "UCRTBASED.DLL"},
    {"_read", "UCRTBASE.DLL"},
    {"_read", "UCRTBASED.DLL"},
};

void
hash_args(char * argHash, fileArgHash * fStruct){
    std::vector<unsigned char> blob_vec((unsigned char *) fStruct,
        ((unsigned char *) fStruct) + sizeof(fileArgHash));
    std::string hash_str;
    picosha2::hash256_hex_string(blob_vec, hash_str);
    argHash[SL2_HASH_LEN] = 0;
    memcpy((void *) argHash, hash_str.c_str(), SL2_HASH_LEN);
}

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
isFunctionTargeted(Function function, client_read_info* info)
{
    const char *func_name = function_to_string(function);

    for (targetFunction t : parsedJson){
        if (t.selected && STREQ(t.functionName.c_str(), func_name)) {
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

// TODO(ww): Document the fallback values here.
SL2_EXPORT
void from_json(const json& j, targetFunction& t)
{
    t.selected      = j.value("selected", false);
    t.index         = j.value("callCount", -1);
    t.mode          = j.value("mode", MATCH_INDEX);
    t.retAddrOffset = j.value("retAddrOffset", -1);
    t.functionName  = j.value("func_name", "");
    t.argHash       = j.value("argHash", "");
    t.buffer        = j["buffer"].get<vector<uint8_t>>();
}

SL2_EXPORT
const char *function_to_string(Function function)
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
        case Function::_read:
            return "_read";
    }

    return "unknown";
}

SL2_EXPORT
const char *exception_to_string(DWORD exception_code)
{
    char *exception_str;

    switch (exception_code) {
        case EXCEPTION_ACCESS_VIOLATION:
            exception_str = "EXCEPTION_ACCESS_VIOLATION";
            break;
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            exception_str = "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
            break;
        case EXCEPTION_BREAKPOINT:
            exception_str = "EXCEPTION_BREAKPOINT";
            break;
        case EXCEPTION_DATATYPE_MISALIGNMENT:
            exception_str = "EXCEPTION_DATATYPE_MISALIGNMENT";
            break;
        case EXCEPTION_FLT_DENORMAL_OPERAND:
            exception_str = "EXCEPTION_FLT_DENORMAL_OPERAND";
            break;
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
            exception_str = "EXCEPTION_FLT_DIVIDE_BY_ZERO";
            break;
        case EXCEPTION_FLT_INEXACT_RESULT:
            exception_str = "EXCEPTION_FLT_INEXACT_RESULT";
            break;
        case EXCEPTION_FLT_INVALID_OPERATION:
            exception_str = "EXCEPTION_FLT_INVALID_OPERATION";
            break;
        case EXCEPTION_FLT_OVERFLOW:
            exception_str = "EXCEPTION_FLT_OVERFLOW";
            break;
        case EXCEPTION_FLT_STACK_CHECK:
            exception_str = "EXCEPTION_FLT_STACK_CHECK";
            break;
        case EXCEPTION_FLT_UNDERFLOW:
            exception_str = "EXCEPTION_FLT_UNDERFLOW";
            break;
        case EXCEPTION_ILLEGAL_INSTRUCTION:
            exception_str = "EXCEPTION_ILLEGAL_INSTRUCTION";
            break;
        case EXCEPTION_IN_PAGE_ERROR:
            exception_str = "EXCEPTION_IN_PAGE_ERROR";
            break;
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
            exception_str = "EXCEPTION_INT_DIVIDE_BY_ZERO";
            break;
        case EXCEPTION_INT_OVERFLOW:
            exception_str = "EXCEPTION_INT_OVERFLOW";
            break;
        case EXCEPTION_INVALID_DISPOSITION:
            exception_str = "EXCEPTION_INVALID_DISPOSITION";
            break;
        case EXCEPTION_NONCONTINUABLE_EXCEPTION:
            exception_str = "EXCEPTION_NONCONTINUABLE_EXCEPTION";
            break;
        case EXCEPTION_PRIV_INSTRUCTION:
            exception_str = "EXCEPTION_PRIV_INSTRUCTION";
            break;
        case EXCEPTION_SINGLE_STEP:
            exception_str = "EXCEPTION_SINGLE_STEP";
            break;
        case EXCEPTION_STACK_OVERFLOW:
            exception_str = "EXCEPTION_STACK_OVERFLOW";
            break;
        case STATUS_HEAP_CORRUPTION:
            exception_str = "STATUS_HEAP_CORRUPTION";
            break;
        default:
            exception_str = "EXCEPTION_SL2_UNKNOWN";
            break;
    }

    return exception_str;
}

SL2_EXPORT
bool function_is_in_expected_module(const char *func, const char *mod)
{
    for (int i = 0; i < SL2_FUNCMOD_TABLE_SIZE; i++) {
        if (STREQ(func, SL2_FUNCMOD_TABLE[i].func) && STREQI(mod, SL2_FUNCMOD_TABLE[i].mod)) {
            return true;
        }
    }

    return false;
}
