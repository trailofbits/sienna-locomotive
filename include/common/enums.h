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
    fread_s,
};

enum {
    MATCH_INDEX = 1 << 0,
    MATCH_RETN_ADDRESS = 1 << 1,
    MATCH_ARG_HASH = 1 << 2,
};

#endif
