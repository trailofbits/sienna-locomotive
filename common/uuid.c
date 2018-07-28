#include <strsafe.h>
#include <wchar.h>

#include "common/uuid.h"

SL2_EXPORT
void sl2_uuid_to_wstring(UUID uuid, wchar_t dst[SL2_UUID_SIZE])
{
    StringCchPrintf(dst, SL2_UUID_SIZE, SL2_UUID_FMT,
        uuid.Data1, uuid.Data2, uuid.Data3, uuid.Data4[0],
        uuid.Data4[1], uuid.Data4[2], uuid.Data4[3], uuid.Data4[4],
        uuid.Data4[5], uuid.Data4[6], uuid.Data4[7]);
}

SL2_EXPORT
void sl2_uuid_to_string(UUID uuid, char dst[SL2_UUID_SIZE])
{
    StringCchPrintfA(dst, SL2_UUID_SIZE, SL2_UUID_FMT_A,
        uuid.Data1, uuid.Data2, uuid.Data3, uuid.Data4[0],
        uuid.Data4[1], uuid.Data4[2], uuid.Data4[3], uuid.Data4[4],
        uuid.Data4[5], uuid.Data4[6], uuid.Data4[7]);
}

SL2_EXPORT
void sl2_string_to_uuid(const char *uuid, UUID *dst)
{
    sscanf_s(uuid, SL2_UUID_FMT_A, &(dst->Data1), &(dst->Data2), &(dst->Data3),
        &(dst->Data4[0]), &(dst->Data4[1]), &(dst->Data4[2]), &(dst->Data4[3]),
        &(dst->Data4[4]), &(dst->Data4[5]), &(dst->Data4[6]), &(dst->Data4[7]));
}
