#ifndef SL2_UUID_H
#define SL2_UUID_H

#include <Windows.h>
#include <Rpc.h>

#include "common/util.h"

// 32 hexadecimal characters, 4 dashes, and a NULL.
#define SL2_UUID_SIZE (37)
#define SL2_UUID_FMT (L"%08x-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx")

// TODO(ww): Remove this and use just the wide format above.
#define SL2_UUID_FMT_A ("%08x-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx")

// Transforms a UUID structure into a human-readable (wide) string.
// NOTE(ww): This function exists because we can't load the Windows RPC
// library that contains its equivalent within DynamoRIO clients.
SL2_EXPORT
void sl2_uuid_to_wstring(UUID uuid, wchar_t dst[SL2_UUID_SIZE]);

// Transforms a UUID structure into a human-readable string.
// NOTE(ww): This function exists because we can't load the Windows RPC
// library that contains its equivalent within DynamoRIO clients.
SL2_EXPORT
void sl2_uuid_to_string(UUID uuid, char dst[SL2_UUID_SIZE]);

// Transforms a human-readable string into a UUID structure.
// NOTE(ww): This function exists because we can't load the Windows RPC
// library that contains its equivalent within DynamoRIO clients.
// This should also really take a wchar_t array like sl2_uuid_to_wstring,
// but I haven't tracked down the bug blocking it in UUID ingestion.
SL2_EXPORT
void sl2_string_to_uuid(const char *uuid, UUID *dst);

#endif
