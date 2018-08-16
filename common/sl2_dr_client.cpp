#include "vendor/picosha2.h"

#include "common/sl2_dr_client.hpp"

using namespace std;

// NOTE(ww): As of Windows 10, both KERNEL32.dll and ADVAPI32.dll
// get forwarded to KERNELBASE.DLL, apparently.
// TODO(ww): Since we iterate over these, order them by likelihood of occurrence?
sl2_funcmod SL2_FUNCMOD_TABLE[] = {
    {"ReadFile", "KERNELBASE.DLL"},
    {"recv", "WS2_32.DLL"},                     // TODO(ww): Is this right?
    {"WinHttpReadData", "WINHTTP.DLL"},         // TODO(ww): Is this right?
    {"InternetReadFile", "WININET.DLL"},        // TODO(ww): Is this right?
    {"WinHttpWebSocketReceive", "WINHTTP.DLL"}, // TODO(ww): Is this right?
    {"RegQueryValueExA", "KERNELBASE.DLL"},
    {"RegQueryValueExW", "KERNELBASE.DLL"},
    {"ReadEventLogA", "KERNELBASE.DLL"},
    {"ReadEventLogW", "KERNELBASE.DLL"},
    {"fread", "UCRTBASE.DLL"},
    {"fread", "UCRTBASED.DLL"},
    {"fread_s", "UCRTBASE.DLL"},
    {"fread_s", "UCRTBASED.DLL"},
    {"_read", "UCRTBASE.DLL"},
    {"_read", "UCRTBASED.DLL"},
};

SL2_EXPORT
void hash_args(char * argHash, fileArgHash * fStruct){
    std::vector<unsigned char> blob_vec((unsigned char *) fStruct,
        ((unsigned char *) fStruct) + sizeof(fileArgHash));
    std::string hash_str;
    picosha2::hash256_hex_string(blob_vec, hash_str);
    argHash[SL2_HASH_LEN] = 0;
    memcpy((void *) argHash, hash_str.c_str(), SL2_HASH_LEN);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// SL2Client
//
// Intended to be for common functionality for DynamoRio clients. This should be moved inside
// the DR build process eventually and be the superclass of Fuzzer and Tracer subclasses.
/////////////////////////////////////////////////////////////////////////////////////////////////
SL2Client::SL2Client() {

}


///////////////////////////////////////////////////////////////////////////////////////////////////
// isFunctionTargeted()
//
// Returns true if the current function should be targeted.
bool SL2Client::
isFunctionTargeted(Function function, client_read_info* info)
{
    const char *func_name = function_to_string(function);

    for (targetFunction t : parsedJson){
        if (t.selected && STREQ(t.functionName.c_str(), func_name)) {
                if (t.mode & MATCH_INDEX)           { if (compare_indices(t, function)) {return true;}}
                if (t.mode & MATCH_RETN_ADDRESS)    { if (compare_return_addresses(t, info)) {return true;}}
                if (t.mode & MATCH_ARG_HASH)        { if (compare_arg_hashes(t, info)) {return true;}}
                if (t.mode & MATCH_ARG_COMPARE)     { if (compare_arg_buffers(t, info)) {return true;}}
                if (t.mode & MATCH_FILENAMES)       { if (compare_filenames(t, info)) {return true;}}
                if (t.mode & MATCH_RETN_COUNT)      { if (compare_index_at_retaddr(t, info)) {return true;}}
                if (t.mode & LOW_PRECISION) {
                    if (info->source) { // if filename is available
                        if (compare_filenames(t, info)) {return true;}
                    } else {
                        if (compare_return_addresses(t, info) && compare_arg_buffers(t, info)) {return true;}
                    }
                }
                if (t.mode & MEDIUM_PRECISION) {
                    if (compare_arg_hashes(t, info) && compare_return_addresses(t, info)) {return true;}
                }
                if (t.mode & HIGH_PRECISION) {
                    if (compare_arg_hashes(t, info) && compare_index_at_retaddr(t, info)) {return true;}
                }
                else {return false;}
        }
    }
    return false;
}

bool SL2Client::compare_filenames(targetFunction &t, client_read_info* info){
    return !wcscmp(t.source.c_str(), info->source);
}

bool SL2Client::compare_indices(targetFunction &t, Function &function){
    return call_counts[function] == t.index;
}

bool SL2Client::compare_index_at_retaddr(targetFunction &t, client_read_info* info){
    return ret_addr_counts[info->retAddrOffset] == t.retAddrCount;
}

bool SL2Client::compare_return_addresses(targetFunction &t, client_read_info* info){
    // Get around ASLR by only examining the bottom bits. This is something of a cheap hack and we should
    // ideally store a copy of the memory map in every run
    uint64_t left = t.retAddrOffset & SUB_ASLR_BITS;
    uint64_t right = info->retAddrOffset & SUB_ASLR_BITS;
    // SL2_DR_DEBUG("Comparing 0x%llx to 0x%llx (%s)\n", left, right, left == right ? "True" : "False");
    return left == right;
}

bool SL2Client::compare_arg_hashes(targetFunction &t, client_read_info* info){
    return STREQ(t.argHash.c_str(), info->argHash);
}

bool SL2Client::compare_arg_buffers(targetFunction &t, client_read_info* info){ // Not working
    size_t minimum = min(16, t.buffer.size());
    if( info->lpNumberOfBytesRead ) {
        minimum = min( minimum, *info->lpNumberOfBytesRead) ;
    }
    else{
        SL2_DR_DEBUG("[!] Couldn't get the size of the buffer! There's a small chance this could cause a segfault\n");
    }

    return !memcmp(t.buffer.data(), info->lpBuffer, minimum);
}

// Returns true if the function targets identified by the client can be used with
// a coverage arena.
//
// NOTE(ww): Eventually, this should always be true. However, for the time being,
// we're using the "index" targeting mode to create a stable identifier for a
// coverage arena. As such, only function targets that were created with that
// mode are currently arena-compatible.
bool SL2Client::
areTargetsArenaCompatible()
{
    for (targetFunction t : parsedJson) {
        if (t.mode != MATCH_INDEX) {
            return false;
        }
    }

    return true;
}

// Generates an arena ID based upon the indices and names of the client's targeted functions.
// `id` *must* be large enough to hold `SL2_HASH_LEN + 1` widechars.
void SL2Client::
generateArenaId(wchar_t *id)
{
    picosha2::hash256_one_by_one hasher;

    for (targetFunction t : parsedJson) {
        std::string index = std::to_string(t.index);

        hasher.process(index.begin(), index.end());
        hasher.process(t.functionName.begin(), t.functionName.end());
    }

    hasher.finish();

    // NOTE(ww): This cheeses C++ into using a stack-allocated string.
    // We do this because allocating a std::string within picosha2 freaks
    // DynamoRIO out. I'm not proud of it.
    char cheese[SL2_HASH_LEN + 1] = {0};
    std::string stdcheese(cheese);

    picosha2::get_hash_hex_string(hasher, stdcheese);
    mbstowcs_s(NULL, id, SL2_HASH_LEN + 1, stdcheese.c_str(), SL2_HASH_LEN);
    id[SL2_HASH_LEN] = '\0';
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// incrementCallCountForFunction()
//
// Increments the total number of call counts for this function
uint64_t    SL2Client::
incrementCallCountForFunction(Function function) {
    return call_counts[function]++;
}

uint64_t    SL2Client::
incrementRetAddrCount(uint64_t retAddr) {
    return ret_addr_counts[retAddr]++;
}


///////////////////////////////////////////////////////////////////////////////////////////////////
// loadJson()
//
// Loads json blob into client
// TODO(ww): Rename to loadTargets, to reflect the fact that we're not using JSON anymore?
bool SL2Client::
loadJson(string path)
{
    file_t targets = dr_open_file(path.c_str(), DR_FILE_READ);
    size_t targets_size;
    size_t txsize;

    dr_file_size(targets, &targets_size);
    uint8_t *buffer = (uint8_t *) dr_global_alloc(targets_size);

    txsize = dr_read_file(targets, buffer, targets_size);
    dr_close_file(targets);

    if (txsize != targets_size) {
        dr_global_free(buffer, targets_size);
        return false;
    }

    std::vector<std::uint8_t> msg(buffer, buffer + targets_size);

    parsedJson = json::from_msgpack(msg);

    dr_global_free(buffer, targets_size);

    return parsedJson.is_array();
}

/*
  The next several functions are wrappers that DynamoRIO calls before each of the targeted functions runs. Each of them
  records metadata about the target function call for use later.
*/

/*
    bool ReadEventLog(
      _In_  HANDLE hEventLog,
      _In_  DWORD  dwReadFlags,
      _In_  DWORD  dwRecordOffset,
      _Out_ LPVOID lpBuffer,
      _In_  DWORD  nNumberOfBytesToRead,
      _Out_ DWORD  *pnBytesRead,
      _Out_ DWORD  *pnMinNumberOfBytesNeeded
    );

    Return: If the function succeeds, the return value is nonzero.
*/
void
SL2Client::wrap_pre_ReadEventLog(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_ReadEventLog>\n");
    HANDLE hEventLog = (HANDLE)drwrap_get_arg(wrapcxt, 0);
    #pragma warning(suppress: 4311 4302)
    DWORD  dwReadFlags = (DWORD)drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    DWORD  dwRecordOffset = (DWORD)drwrap_get_arg(wrapcxt, 2);
    void *lpBuffer = (void *)drwrap_get_arg(wrapcxt, 3);
    #pragma warning(suppress: 4311 4302)
    DWORD  nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 4);
    DWORD  *pnBytesRead = (DWORD *)drwrap_get_arg(wrapcxt, 5);
    DWORD  *pnMinNumberOfBytesNeeded = (DWORD *)drwrap_get_arg(wrapcxt, 6);

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::ReadEventLog;
    info->hFile                = hEventLog;
    info->lpBuffer             = lpBuffer;
    info->nNumberOfBytesToRead = nNumberOfBytesToRead;
    info->lpNumberOfBytesRead  = pnBytesRead;
    info->position             = 0;
    info->retAddrOffset        = (uint64_t) drwrap_get_retaddr(wrapcxt) - baseAddr;

    fileArgHash fStruct = {0};

    GetFinalPathNameByHandle(hEventLog, fStruct.fileName, MAX_PATH, FILE_NAME_NORMALIZED);
    fStruct.position = dwRecordOffset;
    fStruct.readSize = nNumberOfBytesToRead;

    info->argHash = (char *) dr_thread_alloc(drwrap_get_drcontext(wrapcxt), SL2_HASH_LEN + 1);
    hash_args(info->argHash, &fStruct);
}


/*
    LONG WINAPI RegQueryValueEx(
      _In_        HKEY    hKey,
      _In_opt_    LPCTSTR lpValueName,
      _Reserved_  LPDWORD lpReserved,
      _Out_opt_   LPDWORD lpType,
      _Out_opt_   LPBYTE  lpData,
      _Inout_opt_ LPDWORD lpcbData
    );

    Return: If the function succeeds, the return value is ERROR_SUCCESS.
*/
void
SL2Client::wrap_pre_RegQueryValueEx(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_RegQueryValueEx>\n");
    HKEY    hKey = (HKEY)drwrap_get_arg(wrapcxt, 0);
    LPCTSTR lpValueName = (LPCTSTR)drwrap_get_arg(wrapcxt, 1);
    LPDWORD lpReserved = (LPDWORD)drwrap_get_arg(wrapcxt, 2);
    LPDWORD lpType = (LPDWORD)drwrap_get_arg(wrapcxt, 3);
    LPBYTE  lpData = (LPBYTE)drwrap_get_arg(wrapcxt, 4);
    LPDWORD lpcbData = (LPDWORD)drwrap_get_arg(wrapcxt, 5);

    if (lpData != NULL && lpcbData != NULL) {
        *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
        client_read_info *info = (client_read_info *) *user_data;


        info->function             = Function::RegQueryValueEx;
        info->hFile                = hKey;
        info->lpBuffer             = lpData;
        info->nNumberOfBytesToRead = *lpcbData;
        info->lpNumberOfBytesRead  = lpcbData;
        info->position             = 0;
        info->retAddrOffset        = (uint64_t) drwrap_get_retaddr(wrapcxt) - baseAddr;

        fileArgHash fStruct = {0};

//        mbstowcs_s(fStruct.fileName, , lpValueName, MAX_PATH);
        fStruct.readSize = *lpcbData;

        info->argHash = (char *) dr_thread_alloc(drwrap_get_drcontext(wrapcxt), SL2_HASH_LEN + 1);
        hash_args(info->argHash, &fStruct);
    } else {
        *user_data = NULL;
    }
}


/*
    DWORD WINAPI WinHttpWebSocketReceive(
      _In_  HINTERNET                      hWebSocket,
      _Out_ PVOID                          pvBuffer,
      _In_  DWORD                          dwBufferLength,
      _Out_ DWORD                          *pdwBytesRead,
      _Out_ WINHTTP_WEB_SOCKET_BUFFER_TYPE *peBufferType
    );

    Return: NO_ERROR on success. Otherwise an error code.
*/
void
SL2Client::wrap_pre_WinHttpWebSocketReceive(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_WinHttpWebSocketReceive>\n");
    HINTERNET hRequest = (HINTERNET)drwrap_get_arg(wrapcxt, 0);
    PVOID pvBuffer = drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    DWORD dwBufferLength = (DWORD)drwrap_get_arg(wrapcxt, 2);
    PDWORD pdwBytesRead = (PDWORD)drwrap_get_arg(wrapcxt, 3);
    #pragma warning(suppress: 4311 4302)
    WINHTTP_WEB_SOCKET_BUFFER_TYPE peBufferType = (WINHTTP_WEB_SOCKET_BUFFER_TYPE)(int)drwrap_get_arg(wrapcxt, 3);

    // TODO: put this in another file cause you can't import wininet and winhttp
    // LONG positionHigh = 0;
    // DWORD positionLow = InternetSetFilePointer(hRequest, 0, &positionHigh, FILE_CURRENT);
    // uint64_t position = positionHigh;

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::WinHttpWebSocketReceive;
    info->hFile                = hRequest;
    info->lpBuffer             = pvBuffer;
    info->nNumberOfBytesToRead = dwBufferLength;
    info->lpNumberOfBytesRead  = pdwBytesRead;
    info->position             = 0;
    info->retAddrOffset        = (uint64_t) drwrap_get_retaddr(wrapcxt) - baseAddr;

    fileArgHash fStruct = {0};

//    fStruct.fileName[0] = (wchar_t) s;
    fStruct.readSize = dwBufferLength;

    info->argHash = (char *) dr_thread_alloc(drwrap_get_drcontext(wrapcxt), SL2_HASH_LEN + 1);
    hash_args(info->argHash, &fStruct);
}

/*
    bool InternetReadFile(
      _In_  HINTERNET hFile,
      _Out_ LPVOID    lpBuffer,
      _In_  DWORD     dwNumberOfBytesToRead,
      _Out_ LPDWORD   lpdwNumberOfBytesRead
    );

    Return: Returns TRUE if successful
*/
void
SL2Client::wrap_pre_InternetReadFile(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_InternetReadFile>\n");
    HINTERNET hFile = (HINTERNET)drwrap_get_arg(wrapcxt, 0);
    void *lpBuffer = drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    DWORD nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 2);
    LPDWORD lpNumberOfBytesRead = (LPDWORD)drwrap_get_arg(wrapcxt, 3);

    // LONG positionHigh = 0;
    // DWORD positionLow = InternetSetFilePointer(hFile, 0, &positionHigh, FILE_CURRENT);
    // uint64_t position = positionHigh;

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::InternetReadFile;
    info->hFile                = hFile;
    info->lpBuffer             = lpBuffer;
    info->nNumberOfBytesToRead = nNumberOfBytesToRead;
    info->lpNumberOfBytesRead  = lpNumberOfBytesRead;
    info->position             = 0;
    info->retAddrOffset        = (uint64_t) drwrap_get_retaddr(wrapcxt) - baseAddr;

    fileArgHash fStruct = {0};

//    fStruct.fileName[0] = (wchar_t) s;
    fStruct.readSize = nNumberOfBytesToRead;

    info->argHash = (char *) dr_thread_alloc(drwrap_get_drcontext(wrapcxt), SL2_HASH_LEN + 1);
    hash_args(info->argHash, &fStruct);
}

/*
    bool WINAPI WinHttpReadData(
      _In_  HINTERNET hRequest,
      _Out_ LPVOID    lpBuffer,
      _In_  DWORD     dwNumberOfBytesToRead,
      _Out_ LPDWORD   lpdwNumberOfBytesRead
    );

    Return: Returns TRUE if successful
*/
void
SL2Client::wrap_pre_WinHttpReadData(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_WinHttpReadData>\n");
    HINTERNET hRequest = (HINTERNET)drwrap_get_arg(wrapcxt, 0);
    void *lpBuffer = drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    DWORD nNumberOfBytesToRead = (DWORD) drwrap_get_arg(wrapcxt, 2);
    DWORD *lpNumberOfBytesRead = (DWORD *) drwrap_get_arg(wrapcxt, 3);

    // LONG positionHigh = 0;
    // DWORD positionLow = InternetSetFilePointer(hRequest, 0, &positionHigh, FILE_CURRENT);
    // uint64_t position = positionHigh;

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::WinHttpReadData;
    info->hFile                = hRequest;
    info->lpBuffer             = lpBuffer;
    info->nNumberOfBytesToRead = nNumberOfBytesToRead;
    info->lpNumberOfBytesRead  = lpNumberOfBytesRead;
    info->position             = 0;
    info->retAddrOffset        = (uint64_t) drwrap_get_retaddr(wrapcxt) - baseAddr;

    fileArgHash fStruct = {0};

//    fStruct.fileName[0] = (wchar_t) s;
    fStruct.readSize = nNumberOfBytesToRead;

    info->argHash = (char *) dr_thread_alloc(drwrap_get_drcontext(wrapcxt), SL2_HASH_LEN + 1);
    hash_args(info->argHash, &fStruct);
}


/*
    int recv(
      _In_  SOCKET s,
      _Out_ char   *buf,
      _In_  int    len,
      _In_  int    flags
    );

    Return: recv returns the number of bytes received
*/
void
SL2Client::wrap_pre_recv(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_recv>\n");
    SOCKET s  = (SOCKET)drwrap_get_arg(wrapcxt, 0);
    char *buf = (char *)drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    int len   = (int)drwrap_get_arg(wrapcxt, 2);
    #pragma warning(suppress: 4311 4302)
    int flags = (int)drwrap_get_arg(wrapcxt, 3);

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::recv;
    info->hFile                = NULL;
    info->lpBuffer             = buf;
    info->nNumberOfBytesToRead = len;
    info->lpNumberOfBytesRead  = NULL;
    info->position             = 0;
    info->retAddrOffset        = (uint64_t) drwrap_get_retaddr(wrapcxt) - baseAddr;

    fileArgHash fStruct = {0};

    fStruct.fileName[0] = (wchar_t) s;
    fStruct.readSize = len;

    info->argHash = (char *) dr_thread_alloc(drwrap_get_drcontext(wrapcxt), SL2_HASH_LEN + 1);
    hash_args(info->argHash, &fStruct);
}

/*
    bool WINAPI ReadFile(
      _In_        HANDLE       hFile,
      _Out_       LPVOID       lpBuffer,
      _In_        DWORD        nNumberOfBytesToRead,
      _Out_opt_   LPDWORD      lpNumberOfBytesRead,
      _Inout_opt_ LPOVERLAPPED lpOverlapped
    );

    Return: If the function succeeds, the return value is nonzero (TRUE).
*/
void
SL2Client::wrap_pre_ReadFile(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_ReadFile>\n");
    HANDLE hFile                = drwrap_get_arg(wrapcxt, 0);
    void *lpBuffer             = drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    DWORD nNumberOfBytesToRead  = (DWORD)drwrap_get_arg(wrapcxt, 2);
    DWORD *lpNumberOfBytesRead = (DWORD*)drwrap_get_arg(wrapcxt, 3);

    fileArgHash fStruct = {0};

    LARGE_INTEGER offset = {0};
    LARGE_INTEGER position = {0};
    SetFilePointerEx(hFile, offset, &position, FILE_CURRENT);

    GetFinalPathNameByHandle(hFile, fStruct.fileName, MAX_PATH, FILE_NAME_NORMALIZED);
    fStruct.position = position.QuadPart;
    fStruct.readSize = nNumberOfBytesToRead;

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::ReadFile;
    info->hFile                = hFile;
    info->lpBuffer             = lpBuffer;
    info->nNumberOfBytesToRead = nNumberOfBytesToRead;
    info->lpNumberOfBytesRead  = lpNumberOfBytesRead;
    info->position             = fStruct.position;
    info->retAddrOffset        = (uint64_t) drwrap_get_retaddr(wrapcxt) - baseAddr;

    info->source = (wchar_t *) dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(fStruct.fileName));
    memcpy(info->source, fStruct.fileName, sizeof(fStruct.fileName));

    info->argHash = (char *) dr_thread_alloc(drwrap_get_drcontext(wrapcxt), SL2_HASH_LEN + 1);
    hash_args(info->argHash, &fStruct);
}

void
SL2Client::wrap_pre_fread_s(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_fread_s>\n");
    void *buffer = (void *)drwrap_get_arg(wrapcxt, 0);
    size_t bufsize = (size_t)drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    size_t size  = (size_t)drwrap_get_arg(wrapcxt, 2);
    #pragma warning(suppress: 4311 4302)
    size_t count = (size_t)drwrap_get_arg(wrapcxt, 3);
    FILE *file   = (FILE *)drwrap_get_arg(wrapcxt, 4);

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::fread_s;
    // TODO(ww): Figure out why _get_osfhandle breaks DR.
    // info->hFile             = (HANDLE) _get_osfhandle(_fileno(file));
    info->hFile                = NULL;
    info->lpBuffer             = buffer;
    info->nNumberOfBytesToRead = size * count;
    info->lpNumberOfBytesRead  = NULL;
    info->position             = NULL;
    info->retAddrOffset        = (uint64_t) drwrap_get_retaddr(wrapcxt) - baseAddr;

    fileArgHash fStruct = {0};

    fStruct.fileName[0] = (wchar_t) _fileno(file);

    fStruct.position = bufsize;  // Field names don't actually matter
    fStruct.readSize = size;
    fStruct.count = count;

    info->argHash = (char *) dr_thread_alloc(drwrap_get_drcontext(wrapcxt), SL2_HASH_LEN + 1);
    hash_args(info->argHash, &fStruct);
}

void
SL2Client::wrap_pre_fread(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre_fread>\n");

    void *buffer = (void *)drwrap_get_arg(wrapcxt, 0);
    #pragma warning(suppress: 4311 4302)
    size_t size  = (size_t)drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    size_t count = (size_t)drwrap_get_arg(wrapcxt, 2);
    FILE *file   = (FILE *)drwrap_get_arg(wrapcxt, 3);

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::fread;
    // TODO(ww): Figure out why _get_osfhandle breaks DR.
    // info->hFile             = (HANDLE) _get_osfhandle(_fileno(file));
    info->hFile                = NULL;
    info->lpBuffer             = buffer;
    info->nNumberOfBytesToRead = size * count;
    info->lpNumberOfBytesRead  = NULL;
    info->position             = NULL;
    info->retAddrOffset        = (uint64_t) drwrap_get_retaddr(wrapcxt) - baseAddr;

    fileArgHash fStruct = {0};

    fStruct.fileName[0] = (wchar_t) _fileno(file);

//    fStruct.position = ftell(fpointer);  // This instantly crashes DynamoRIO
    fStruct.readSize = size;
    fStruct.count = count;

    info->argHash = (char *) dr_thread_alloc(drwrap_get_drcontext(wrapcxt), SL2_HASH_LEN + 1);
    hash_args(info->argHash, &fStruct);
}

void
SL2Client::wrap_pre__read(void *wrapcxt, OUT void **user_data)
{
    SL2_DR_DEBUG("<in wrap_pre__read>\n");

    #pragma warning(suppress: 4311 4302)
    int fd = (int) drwrap_get_arg(wrapcxt, 0);
    void *buffer = drwrap_get_arg(wrapcxt, 1);
    #pragma warning(suppress: 4311 4302)
    unsigned int count = (unsigned int) drwrap_get_arg(wrapcxt, 2);

    *user_data             = dr_thread_alloc(drwrap_get_drcontext(wrapcxt), sizeof(client_read_info));
    client_read_info *info = (client_read_info *) *user_data;

    info->function             = Function::_read;
    // TODO(ww): Figure out why _get_osfhandle breaks DR.
    // info->hFile             = (HANDLE) _get_osfhandle(fd);
    info->hFile                = NULL;
    info->lpBuffer             = buffer;
    info->nNumberOfBytesToRead = count;
    info->lpNumberOfBytesRead  = NULL;
    info->position             = NULL;
    info->retAddrOffset        = (uint64_t) drwrap_get_retaddr(wrapcxt) - baseAddr;

    fileArgHash fStruct = {0};

    fStruct.fileName[0] = (wchar_t) fd;
    fStruct.count= count;

    info->argHash = (char *) dr_thread_alloc(drwrap_get_drcontext(wrapcxt), SL2_HASH_LEN + 1);
    hash_args(info->argHash, &fStruct);
}


// TODO(ww): Document the fallback values here.
SL2_EXPORT
void from_json(const json& j, targetFunction& t)
{
    t.selected      = j.value("selected", false);
    t.index         = j.value("callCount", -1);
    t.retAddrCount  = j.value("retAddrCount", -1);
    t.mode          = j.value("mode", MATCH_INDEX); // TODO - might want to chose a more sensible default
    t.retAddrOffset = j.value("retAddrOffset", -1);
    t.functionName  = j.value("func_name", "");
    t.argHash       = j.value("argHash", "");
    t.buffer        = j["buffer"].get<vector<uint8_t>>();

    string source        = j.value("source", "");
    wstring wsource;
    wsource.assign(source.begin(), source.end());
    t.source = wsource;
}

SL2_EXPORT
const char *function_to_string(Function function)
{
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
        case Function::_read:
            return "_read";
    }

    return "unknown";
}

SL2_EXPORT
const char *exception_to_string(DWORD exception_code)
{
    char *exception_str;

    switch (exception_code) {
        case EXCEPTION_ACCESS_VIOLATION:
            exception_str = "EXCEPTION_ACCESS_VIOLATION";
            break;
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            exception_str = "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
            break;
        case EXCEPTION_BREAKPOINT:
            exception_str = "EXCEPTION_BREAKPOINT";
            break;
        case EXCEPTION_DATATYPE_MISALIGNMENT:
            exception_str = "EXCEPTION_DATATYPE_MISALIGNMENT";
            break;
        case EXCEPTION_FLT_DENORMAL_OPERAND:
            exception_str = "EXCEPTION_FLT_DENORMAL_OPERAND";
            break;
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
            exception_str = "EXCEPTION_FLT_DIVIDE_BY_ZERO";
            break;
        case EXCEPTION_FLT_INEXACT_RESULT:
            exception_str = "EXCEPTION_FLT_INEXACT_RESULT";
            break;
        case EXCEPTION_FLT_INVALID_OPERATION:
            exception_str = "EXCEPTION_FLT_INVALID_OPERATION";
            break;
        case EXCEPTION_FLT_OVERFLOW:
            exception_str = "EXCEPTION_FLT_OVERFLOW";
            break;
        case EXCEPTION_FLT_STACK_CHECK:
            exception_str = "EXCEPTION_FLT_STACK_CHECK";
            break;
        case EXCEPTION_FLT_UNDERFLOW:
            exception_str = "EXCEPTION_FLT_UNDERFLOW";
            break;
        case EXCEPTION_ILLEGAL_INSTRUCTION:
            exception_str = "EXCEPTION_ILLEGAL_INSTRUCTION";
            break;
        case EXCEPTION_IN_PAGE_ERROR:
            exception_str = "EXCEPTION_IN_PAGE_ERROR";
            break;
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
            exception_str = "EXCEPTION_INT_DIVIDE_BY_ZERO";
            break;
        case EXCEPTION_INT_OVERFLOW:
            exception_str = "EXCEPTION_INT_OVERFLOW";
            break;
        case EXCEPTION_INVALID_DISPOSITION:
            exception_str = "EXCEPTION_INVALID_DISPOSITION";
            break;
        case EXCEPTION_NONCONTINUABLE_EXCEPTION:
            exception_str = "EXCEPTION_NONCONTINUABLE_EXCEPTION";
            break;
        case EXCEPTION_PRIV_INSTRUCTION:
            exception_str = "EXCEPTION_PRIV_INSTRUCTION";
            break;
        case EXCEPTION_SINGLE_STEP:
            exception_str = "EXCEPTION_SINGLE_STEP";
            break;
        case EXCEPTION_STACK_OVERFLOW:
            exception_str = "EXCEPTION_STACK_OVERFLOW";
            break;
        case STATUS_HEAP_CORRUPTION:
            exception_str = "STATUS_HEAP_CORRUPTION";
            break;
        default:
            exception_str = "EXCEPTION_SL2_UNKNOWN";
            break;
    }

    return exception_str;
}

SL2_EXPORT
bool function_is_in_expected_module(const char *func, const char *mod)
{
    for (int i = 0; i < SL2_FUNCMOD_TABLE_SIZE; i++) {
        if (STREQ(func, SL2_FUNCMOD_TABLE[i].func) && STREQI(mod, SL2_FUNCMOD_TABLE[i].mod)) {
            return true;
        }
    }

    return false;
}
