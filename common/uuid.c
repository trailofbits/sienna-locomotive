#include <strsafe.h>
#include <wchar.h>

#include "common/uuid.h"

// Transforms a UUID structure into a human-readable (wide) string.
// NOTE(ww): This function exists because we can't load the Windows RPC
// library that contains its equivalent within DynamoRIO clients.
__declspec(dllexport) void sl2_uuid_to_wstring(UUID uuid, WCHAR dst[SL2_UUID_SIZE])
{
    StringCchPrintf(dst, SL2_UUID_SIZE, SL2_UUID_FMT,
        uuid.Data1, uuid.Data2, uuid.Data3, uuid.Data4[0],
        uuid.Data4[1], uuid.Data4[2], uuid.Data4[3], uuid.Data4[4],
        uuid.Data4[5], uuid.Data4[6], uuid.Data4[7]);
}

// Transforms a human-readable string into a UUID structure.
// NOTE(ww): This function exists because we can't load the Windows RPC
// library that contains its equivalent within DynamoRIO clients.
// This should also really take a WCHAR array like sl2_uuid_to_wstring,
// but I haven't tracked down the bug blocking it in UUID ingestion.
__declspec(dllexport) void sl2_wstring_to_uuid(const char *uuid, UUID *dst)
{
    DWORD b0, b1, b2, b3, b4, b5, b6, b7;

    sscanf_s(uuid, SL2_UUID_FMT_A, &(dst->Data1), &(dst->Data2), &(dst->Data3),
        &b0, &b1, &b2, &b3, &b4, &b5, &b6, &b7);

    // TODO(ww): Macro or loop this.
    dst->Data4[0] = (BYTE) b0;
    dst->Data4[1] = (BYTE) b1;
    dst->Data4[2] = (BYTE) b2;
    dst->Data4[3] = (BYTE) b3;
    dst->Data4[4] = (BYTE) b4;
    dst->Data4[5] = (BYTE) b5;
    dst->Data4[6] = (BYTE) b6;
    dst->Data4[7] = (BYTE) b7;
}