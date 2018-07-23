#include "common/sl2_dr_client.hpp"

using namespace std;

///////////////////////////////////////////////////////////////////////////////////////////////////
// SL2Client
//
// Intended to be for common functionality for DynamoRio clients. This should be moved inside
// the DR build process eventually and be the superclass of Fuzzer and Tracer subclasses.
///////////////////////////////////////////////////////////////////////////////////////////////////
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
areTargetsArenaCompatible() {
    for (targetFunction t : parsedJson) {
        if (t.mode != MATCH_INDEX) {
            return false;
        }
    }

    return true;
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
void SL2Client::
loadJson(string target) {

    std::ifstream jsonStream(target); // TODO ifstream can sometimes cause performance issues
    jsonStream >> parsedJson;
    if (!parsedJson.is_array()) {
      throw("Document root is not an array\n");
    }

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
