#include "common/sl2_dr_client.hpp"

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
    t.selected = j.value("selected", false);
    t.index = j.value("callCount", -1);
    t.mode = j.value("mode", MATCH_INDEX);
    t.retAddrOffset = j.value("retAddrOffset", -1);
    t.functionName = j.value("func_name", "");
    t.argHash = j.value("argHash", "");
}
