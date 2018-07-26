#ifndef SL2_UTIL_H
#define SL2_UTIL_H

#include <string.h>

// Convenience macros for testing normal and wide strings
// for equality and case equality.
#define STREQ(a, b) (!strcmp(a, b))
#define STREQI(a, b) (!_stricmp(a, b))
#define WSTREQ(a, b) (!wcscmp(a, b))
#define WSTREQI(a, b) (!_wcsicmp(a, b))

#endif
