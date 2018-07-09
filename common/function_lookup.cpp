#include "common/function_lookup.hpp"

__declspec(dllexport) char *get_function_name(Function function) {
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
