#ifndef SL2_ENUMS_H
#define SL2_ENUMS_H

enum class Function {
    ReadFile,
    recv,
    WinHttpReadData,
    InternetReadFile,
    WinHttpWebSocketReceive,
    RegQueryValueEx,
    ReadEventLog,
    fread,
};

enum {
    MATCH_INDEX = 1 << 0,
    MATCH_CALL_ADDRESS = 1 << 1,
};

#endif
