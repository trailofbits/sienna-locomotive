#ifndef SL2_UTIL_H
#define SL2_UTIL_H

#include <string.h>

#define SL2_EXPORT __declspec(dllexport)

// The size of a SHA256 hash.
#define SL2_HASH_LEN 64

// The maximum length of a target application's arguments (including program name and NULL).
// NOTE(ww): This is based on the maximum argument length on the command line,
// *not* the maximum length accepted by either CreateProcess or other WinAPI functions.
// As such, it's mostly arbitrary.
#define SL2_ARGV_LEN 8192

// Convenience macros for testing normal and wide strings
// for equality and case equality.
#define STREQ(a, b) (!strcmp(a, b))
#define STREQI(a, b) (!_stricmp(a, b))
#define WSTREQ(a, b) (!wcscmp(a, b))
#define WSTREQI(a, b) (!_wcsicmp(a, b))

#endif
