#ifndef SL2_UUID_H
#define SL2_UUID_H

#include <Windows.h>
#include <Rpc.h>

// 32 hexadecimal characters, 4 dashes, and a NULL.
#define SL2_UUID_SIZE (37)
#define SL2_UUID_FMT (L"%08x-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx")

// TODO(ww): Remove this and use just the wide format above.
#define SL2_UUID_FMT_A ("%08x-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx")

__declspec(dllexport) void sl2_uuid_to_wstring(UUID uuid, wchar_t dst[SL2_UUID_SIZE]);
__declspec(dllexport) void sl2_wstring_to_uuid(const char *uuid, UUID *dst);

#endif
