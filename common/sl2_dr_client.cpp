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

// TODO(ww): Throw an exception on parse/extraction errors.
__declspec(dllexport) void from_json(const json& j, targetFunction& t)
{
    t.selected = j.at("selected").get<bool>();
    t.index = j.at("callCount").get<int>();
    t.mode = j.at("mode").get<int>();
    t.retAddrOffset = j.at("retAddrOffset").get<int>();
    t.functionName = j.at("func_name").get<std::string>();
    t.argHash = j.at("argHash").get<std::string>();
}
