#ifndef SL2_UTIL_H
#define SL2_UTIL_H

#include <string.h>

#define SL2_EXPORT __declspec(dllexport)

// The size of a SHA256 hash.
#define SL2_HASH_LEN 64

// Convenience macros for testing normal and wide strings
// for equality and case equality.
#define STREQ(a, b) (!strcmp(a, b))
#define STREQI(a, b) (!_stricmp(a, b))
#define WSTREQ(a, b) (!wcscmp(a, b))
#define WSTREQI(a, b) (!_wcsicmp(a, b))

#endif
