#include <algorithm>
#include <random>
#include <set>
#include <map>
#include <cstdlib>
#include <unordered_map>
#include <string.h>
#include <stdio.h>

#define NOMINMAX
#include <Windows.h>
#include <ShlObj.h>
#include <PathCch.h>
#include <Rpc.h>
#include <shellapi.h>
#include <Strsafe.h>

#define LOGURU_IMPLEMENTATION 1
#include "loguru.hpp"

#include "server.hpp"

static CRITICAL_SECTION critId;
static HANDLE hProcessMutex = INVALID_HANDLE_VALUE;

static HANDLE hLog = INVALID_HANDLE_VALUE;

static WCHAR FUZZ_WORKING_PATH[MAX_PATH] = L"";
static WCHAR FUZZ_LOG[MAX_PATH] = L"";

/*
    TODO(ww): Create a formal server API. Doing so will help with:
        1. all of the `exit`s scattered through the current code
        2. iterating on the server protocol without breaking clients
*/


// Called on process termination (by atexit).
static VOID server_cleanup()
{
    LOG_F(INFO, "server_cleanup: Called, cleaning things up");

    // NOTE(ww): We could probably check return codes here, but there's
    // no point -- the process is about to be destroyed anyways.
    ReleaseMutex(hProcessMutex);
    CloseHandle(hProcessMutex);
    DeleteCriticalSection(&critId);
}

// Initialize the global variable (FUZZ_LOG) containing the path to the logging file.
// NOTE(ww): We separate this from initWorkingDir so that we can log any errors that
// happen to occur in initWorkingDir.
VOID initLoggingFile() {
    PWSTR roamingPath;
    SHGetKnownFolderPath(FOLDERID_RoamingAppData, NULL, NULL, &roamingPath);

    if (PathCchCombine(FUZZ_LOG, MAX_PATH, roamingPath, L"Trail of Bits\\fuzzkit\\log\\server.log") != S_OK) {
        LOG_F(ERROR, "initLoggingFile: failed to combine logfile path (0x%x)", GetLastError());
        exit(1);
    }

    CoTaskMemFree(roamingPath);
}

// Initialize the global variables containins the paths to the working directory,
// as well as the subdirectories and files we expect individual runs to produce.
// NOTE(ww): This should be kept up-to-date with fuzzer_config.py.
VOID initWorkingDir() {
    PWSTR roamingPath;
    SHGetKnownFolderPath(FOLDERID_RoamingAppData, NULL, NULL, &roamingPath);
    WCHAR workingLocalPath[MAX_PATH] = L"Trail of Bits\\fuzzkit\\working";

    if (PathCchCombine(FUZZ_WORKING_PATH, MAX_PATH, roamingPath, workingLocalPath) != S_OK) {
        LOG_F(ERROR, "initWorkingDir: failed to combine working dir path (0x%x)", GetLastError());
        exit(1);
    }

    CoTaskMemFree(roamingPath);
}

/* Generates a new run UUID, writes relevant run metadata files into the corresponding run metadata dir
    This, like many things in the server, is pretty overzealous about exiting after any errors, often without an
    explanation of what happened. TODO - fix this */
DWORD generateRunId(HANDLE hPipe) {
    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;
    UUID runId;
    WCHAR *runId_s;

    LOG_F(INFO, "generateRunId: received request");

    // NOTE(ww): On recent versions of Windows, UuidCreate generates a v4 UUID that
    // is sufficiently diffuse for our purposes (avoiding conflicts between runs).
    // See: https://stackoverflow.com/questions/35366368/does-uuidcreate-use-a-csprng
    UuidCreate(&runId);
    UuidToString(&runId, (RPC_WSTR *)&runId_s);

    WCHAR targetDir[MAX_PATH + 1] = {0};
    PathCchCombine(targetDir, MAX_PATH, FUZZ_WORKING_PATH, runId_s);
    if (!CreateDirectory(targetDir, NULL)) {
        LOG_F(ERROR, "generateRunId: couldn't create working directory (0x%x)", GetLastError());
        exit(1);
    }

    WriteFile(hPipe, &runId, sizeof(UUID), &dwBytesWritten, NULL);
    LOG_F(INFO, "generateRunId: generated ID %S", runId_s);

    // get program name
    // TODO(ww): 8192 is the correct buffer size for the Windows command line, but
    // we should try to find a macro in the WINAPI for it here.
    WCHAR commandLine[8192] = {0};
    DWORD size = 0;
    if (!ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "generateRunId: failed to read size of program name (0x%x)", GetLastError());
        exit(1);
    }

    if (size > 8191) {
        LOG_F(ERROR, "generateRunId: program name length > 8191");
        exit(1);
    }

    if (!ReadFile(hPipe, commandLine, size, &dwBytesRead, NULL)) {
        LOG_F(ERROR, "generateRunId: failed to read size of argument list (0x%x)", GetLastError());
        exit(1);
    }

    WCHAR targetFile[MAX_PATH + 1] = { 0 };
    PathCchCombine(targetFile, MAX_PATH, targetDir, FUZZ_RUN_PROGRAM_TXT);
    HANDLE hFile = CreateFileW(targetFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "generateRunId: failed to open program.txt: %S (0x%x)", targetFile, GetLastError());
        exit(1);
    }

    if (!WriteFile(hFile, commandLine, size, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "generateRunId: failed to write program name to program.txt (0x%x)", GetLastError());
        exit(1);
    }

    if (!CloseHandle(hFile)) {
        LOG_F(ERROR, "generateRunId: failed to close program.txt (0x%x)", GetLastError());
        exit(1);
    }

    ZeroMemory(commandLine, 8192 * sizeof(WCHAR));

    // get program arguments
    size = 0;
    if (!ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "generateRunId: failed to read program argument list length (0x%x)", GetLastError());
        exit(1);
    }

    if (size > 8191) {
        LOG_F(ERROR, "generateRunId: program argument list length > 8191");
        exit(1);
    }

    if (!ReadFile(hPipe, commandLine, size, &dwBytesRead, NULL)) {
        LOG_F(ERROR, "generateRunId: failed to read program argument list (0x%x)", GetLastError());
        exit(1);
    }

    ZeroMemory(targetFile, (MAX_PATH + 1) * sizeof(WCHAR));
    PathCchCombine(targetFile, MAX_PATH, targetDir, FUZZ_RUN_ARGUMENTS_TXT);
    hFile = CreateFile(targetFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "generateRunId: failed to open arguments.txt: %S (0x%x)", targetFile, GetLastError());
        exit(1);
    }

    if (!WriteFile(hFile, commandLine, size, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "generateRunId: failed to write argument list to arguments.txt (0x%x)", GetLastError());
        exit(1);
    }

    if (!CloseHandle(hFile)) {
        LOG_F(ERROR, "generateRunId: failed to close arguments.txt (0x%x)", GetLastError());
        exit(1);
    }

    RpcStringFree((RPC_WSTR *)&runId_s);

    LOG_F(INFO, "generateRunId: finished");

    return 0;
}

/*
  Mutation strategies. The server selects one each time the fuzzing harness requests mutated bytes
*/

// TODO(ww): Why are we doing this?
DWORD getRand()
{
    DWORD random = rand();
    random <<= 15;
    random |= rand();

    return random;
}

VOID strategyAAAA(BYTE *buf, size_t size)
{
    memset(buf, 'A', size);
}

VOID strategyFlipBit(BYTE *buf, size_t size)
{
    std::random_device rd;
    srand(rd());

    size_t pos = getRand() % size;
    BYTE byte = buf[pos];

    BYTE mask = 1 << rand() % 8;
    buf[pos] = byte ^ mask;
}

VOID strategyRepeatBytes(BYTE *buf, size_t size)
{
    std::random_device rd;
    srand(rd());

    // pos -> zero to second to last byte
    size_t pos = getRand() % (size - 1);

    // repeat_length -> 1 to (remaining_size - 1)
    size_t size_m2 = size - 2;
    size_t repeat_length = 0;
    if (size_m2 > pos) {
        repeat_length = getRand() % (size_m2 - pos);
    }
    repeat_length++;

    // set start and end
    size_t curr_pos = pos + repeat_length;
    size_t end = getRand() % (size - curr_pos);
    end += curr_pos + 1;

    while (curr_pos < end) {
        buf[curr_pos] = buf[pos];
        curr_pos++;
        pos++;
    }
}

VOID strategyRepeatBytesBackward(BYTE *buf, size_t size)
{
    std::random_device rd;
    srand(rd());

    size_t start = getRand() % (size - 1);
    size_t end = start + getRand() % ((size + 1) - start);

    std::reverse(buf + start, buf + end);
}

VOID strategyDeleteBytes(BYTE *buf, size_t size)
{
    std::random_device rd;
    srand(rd());

    // pos -> zero to second to last byte
    size_t pos = 0;
    if (size > 1) {
        pos = getRand() % (size - 1);
    }

    // delete_length -> 1 to (remaining_size - 1)
    size_t size_m2 = size - 2;
    size_t delete_length = 0;
    if (size_m2 > pos) {
        delete_length = getRand() % (size_m2 - pos);
    }
    delete_length++;

    for (size_t i=0; i<delete_length; i++) {
        buf[pos+i] = 0;
    }
}

VOID strategyRandValues(BYTE *buf, size_t size)
{
    std::random_device rd;
    srand(rd());

    size_t rand_size = 0;
    size_t max = 0;
    while (max < 1) {
        // rand_size -> 1, 2, 4, 8
        rand_size = (size_t) pow(2, getRand() % 4);
        max = (size + 1);
        max -= rand_size;
    }

    // pos -> zero to ((size + 1) - rand_size)
    // e.g. buf size is 16, rand_size is 8
    // max will be from 0 to 9 guanteeing a
    // pos that will fit into the buffer
    size_t pos = getRand() % max;

    for (size_t i=0; i<rand_size; i++) {
        BYTE mut = rand() % 256;
        buf[pos + i] = mut;
    }
}

#define VALUES1 -128, -2, -1, 0, 1, 2, 4, 8, 10, 16, 32, 64, 100, 127, 128, 255
#define VALUES2 -32768, -129, 256, 512, 1000, 1024, 4096, 32767, 65535
#define VALUES4 -2147483648, -100663046, -32769, 32768, 65536, 100663045, 2147483647, 4294967295
#define VALUES8  -9151314442816848000, -2147483649, 2147483648, 4294967296, 432345564227567365, 18446744073709551615

VOID strategyKnownValues(BYTE *buf, size_t size)
{
    INT8 values1[] = { VALUES1 };
    INT16 values2[] = { VALUES1, VALUES2 };
    INT32 values4[] = { VALUES1, VALUES2, VALUES4 };
    INT64 values8[] = { VALUES1, VALUES2, VALUES4, VALUES8 };

    std::random_device rd;
    srand(rd());

    size_t rand_size = 0;
    size_t max = 0;
    while (max < 1) {
        // size -> 1, 2, 4, 8
        rand_size = (size_t) pow(2, getRand() % 4);
        max = (size + 1);
        max -= rand_size;
    }

    // pos -> zero to ((size + 1) - rand_size)
    // e.g. buf size is 16, rand_size is 8
    // max will be from 0 to 9 guaranteeing a
    // pos that will fit into the buffer
    size_t pos = getRand() % max;
    BOOL endian = rand() % 2;

    size_t selection = 0;
    switch (rand_size) {
        case 1:
            selection = getRand() % (sizeof(values1) / sizeof(values1[0]));
            // nibble endianness, because sim cards
            values1[selection] = endian ? values1[selection] >> 4 | values1[selection] << 4 : values1[selection];
            *(UINT8 *)(buf+pos) = values1[selection];
            break;
        case 2:
            selection = getRand() % (sizeof(values2) / sizeof(values2[0]));
            values2[selection] = endian ? _byteswap_ushort(values2[selection]) : values2[selection];
            *(UINT16 *)(buf+pos) = values2[selection];
            break;
        case 4:
            selection = getRand() % (sizeof(values4) / sizeof(values4[0]));
            values4[selection] = endian ? _byteswap_ulong(values4[selection]) : values4[selection];
            *(UINT32 *)(buf+pos) = values4[selection];
            break;
        case 8:
            selection = getRand() % (sizeof(values8) / sizeof(values8[0]));
            values8[selection] = endian ? _byteswap_uint64(values8[selection]) : values8[selection];
            *(UINT64 *)(buf+pos) = values8[selection];
            break;
        default:
            strategyAAAA(buf, size);
            break;
    }
}

VOID strategyAddSubKnownValues(BYTE *buf, size_t size)
{
    INT8 values1[] = { VALUES1 };
    INT16 values2[] = { VALUES1, VALUES2 };
    INT32 values4[] = { VALUES1, VALUES2, VALUES4 };
    INT64 values8[] = { VALUES1, VALUES2, VALUES4, VALUES8 };

    std::random_device rd;
    srand(rd());

    size_t rand_size = 0;
    size_t max = 0;
    while (max < 1) {
        // size -> 1, 2, 4, 8
        rand_size = (size_t) pow(2, getRand() % 4);
        max = (size + 1) - rand_size;
    }

    // pos -> zero to ((size + 1) - rand_size)
    // e.g. buf size is 16, rand_size is 8
    // max will be from 0 to 9 guaranteeing a
    // pos that will fit into the buffer
    size_t pos = getRand() % max;
    BOOL endian = rand() % 2;

    BYTE sub = 1;
    if (rand() % 2) {
        sub = -1;
    }

    size_t selection = 0;
    switch (rand_size) {
        case 1:
            selection = getRand() % (sizeof(values1) / sizeof(values1[0]));
            // nibble endianness, because sim cards
            values1[selection] = endian ? values1[selection] >> 4 | values1[selection] << 4 : values1[selection];
            *(UINT8 *)(buf+pos) += sub * values1[selection];
            break;
        case 2:
            selection = getRand() % (sizeof(values2) / sizeof(values2[0]));
            values2[selection] = endian ? _byteswap_ushort(values2[selection]) : values2[selection];
            *(UINT16 *)(buf+pos) += sub * values2[selection];
            break;
        case 4:
            selection = getRand() % (sizeof(values4) / sizeof(values4[0]));
            values4[selection] = endian ? _byteswap_ulong(values4[selection]) : values4[selection];
            *(UINT32 *)(buf+pos) += sub * values4[selection];
            break;
        case 8:
            selection = getRand() % (sizeof(values8) / sizeof(values8[0]));
            values8[selection] = endian ? _byteswap_uint64(values8[selection]) : values8[selection];
            *(UINT64 *)(buf+pos) += sub * values8[selection];
            break;
        default:
            strategyAAAA(buf, size);
            break;
    }
}

VOID strategyEndianSwap(BYTE *buf, size_t size)
{
    std::random_device rd;
    srand(rd());

    size_t rand_size = 0;
    size_t max = 0;
    while (max < 1) {
        // size -> 1, 2, 4, 8
        rand_size = (size_t) pow(2, getRand() % 4);
        max = (size + 1) - rand_size;
    }

    // pos -> zero to ((size + 1) - rand_size)
    // e.g. buf size is 16, rand_size is 8
    // max will be from 0 to 9 guaranteeing a
    // pos that will fit into the buffer
    size_t pos = getRand() % max;

    switch (rand_size) {
        case 1:
            // nibble endianness, because sim cards
            *(UINT8 *)(buf+pos) = *(UINT8 *)(buf+pos) >> 4 | *(UINT8 *)(buf+pos) << 4;
            break;
        case 2:
            *(UINT16 *)(buf+pos) = _byteswap_ushort(*(UINT16 *)(buf+pos));
            break;
        case 4:
            *(UINT32 *)(buf+pos) = _byteswap_ulong(*(UINT32 *)(buf+pos));
            break;
        case 8:
            *(UINT64 *)(buf+pos) = _byteswap_uint64(*(UINT64 *)(buf+pos));
            break;
        default:
            strategyAAAA(buf, size);
            break;
    }
}

/* Selects a mutations strategy at random */
DWORD mutate(BYTE *buf, size_t size)
{
    // afl for inspiration
    if (size == 0) {
        return 0;
    }

    std::random_device rd;
    srand(rd());

    DWORD choice = getRand() % 8;
    switch (choice) {
        case 0:
            LOG_F(INFO, "mutate: strategyFlipBit");
            strategyFlipBit(buf, size);
            break;
        case 1:
            LOG_F(INFO, "mutate: strategyRandValues");
            strategyRandValues(buf, size);
            break;
        case 2:
            LOG_F(INFO, "mutate: strategyRepeatBytes");
            strategyRepeatBytes(buf, size);
            break;
        case 3:
            LOG_F(INFO, "mutate: strategyKnownValues");
            strategyKnownValues(buf, size);
            break;
        case 4:
            LOG_F(INFO, "mutate: strategyAddSubKnownValues");
            strategyAddSubKnownValues(buf, size);
            break;
        case 5:
            LOG_F(INFO, "mutate: strategyEndianSwap");
            strategyEndianSwap(buf, size);
            break;
        case 6:
            LOG_F(INFO, "mutate: strategyDeleteBytes");
            strategyDeleteBytes(buf, size);
            break;
        case 7:
            LOG_F(INFO, "mutate: strategyRepeatBytesBackward");
            strategyRepeatBytesBackward(buf, size);
            break;
        default:
            LOG_F(INFO, "mutate: strategyAAAA");
            strategyAAAA(buf, size);
            break;
    }

    // TODO(ww): Additional strategies:
    // insert bytes
    // move bytes
    // add random bytes to space
    // inject random NULL(s)

    return 0;
}

/* Writes the fkt file in the event we found a crash. Stores information about the mutation that caused it */
DWORD writeFKT(HANDLE hFile, DWORD type, DWORD pathSize, WCHAR *filePath, size_t position, size_t size, BYTE* buf)
{
    DWORD dwBytesWritten = 0;

    if (!WriteFile(hFile, "FKT\0", 4, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "writeFKT: failed to write FKT header (0x%x)", GetLastError());
        exit(1);
    }

    // only one type for right now, files
    if (!WriteFile(hFile, &type, sizeof(DWORD), &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "writeFKT: failed to write type (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(hFile, &pathSize, sizeof(DWORD), &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "writeFKT: failed to write path size (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(hFile, filePath, pathSize * sizeof(WCHAR), &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "writeFKT: failed to write path (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(hFile, &position, sizeof(size_t), &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "writeFKT: failed to write offset (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(hFile, &size, sizeof(size_t), &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "writeFKT: failed to write buffer size (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(hFile, buf, (DWORD)size, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "writeFKT: failed to write buffer (0x%x)", GetLastError());
        exit(1);
    }

    if (!CloseHandle(hFile)) {
        LOG_F(ERROR, "writeFKT: failed to close FKT (0x%x)", GetLastError());
        exit(1);
    }

    return 0;
}

/* handles mutation requests over the named pipe from the fuzzing harness */
DWORD handleMutation(HANDLE hPipe)
{
    LOG_F(INFO, "handleMutation: starting mutation request");

    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;
    UUID runId;
    WCHAR *runId_s;

    if (!ReadFile(hPipe, &runId, sizeof(UUID), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleMutation: failed to read run ID (0x%x)", GetLastError());
        exit(1);
    }

    UuidToString(&runId, (RPC_WSTR *)&runId_s);

    DWORD type = 0;
    if (!ReadFile(hPipe, &type, sizeof(DWORD), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleMutation: failed to read function type (0x%x)", GetLastError());
        exit(1);
    }

    DWORD mutate_count = 0;
    WCHAR mutate_fname[MAX_PATH + 1] = {0};
    if (!ReadFile(hPipe, &mutate_count, sizeof(DWORD), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleMutation: failed to read mutation count (0x%x)", GetLastError());
        exit(1);
    }
    StringCchPrintfW(mutate_fname, MAX_PATH, FUZZ_RUN_FKT_FMT, mutate_count);

    DWORD pathSize = 0;
    if (!ReadFile(hPipe, &pathSize, sizeof(DWORD), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleMutation: failed to read size of mutation filepath (0x%x)", GetLastError());
        exit(1);
    }

    if (pathSize > MAX_PATH) {
        LOG_F(ERROR, "handleMutation: pathSize > MAX_PATH", GetLastError());
        exit(1);
    }

    WCHAR filePath[MAX_PATH + 1] = {0};

    // NOTE(ww): Interestingly, Windows distinguishes between a read of 0 bytes
    // and no read at all -- both the client and the server have to do either one or the
    // other, and failing to do either on one side causes a truncated read or write.
    if (pathSize > 0) {
        if (!ReadFile(hPipe, &filePath, pathSize * sizeof(WCHAR), &dwBytesRead, NULL)) {
            LOG_F(ERROR, "handleMutation: failed to read mutation filepath (0x%x)", GetLastError());
            exit(1);
        }

        filePath[pathSize] = 0;

        LOG_F(INFO, "handleMutation: mutation file path: %S", filePath);
    }
    else {
        LOG_F(WARNING, "handleMutation: the fuzzer didn't send us a file path!");
    }

    size_t position = 0;
    if (!ReadFile(hPipe, &position, sizeof(size_t), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleMutation: failed to read mutation offset (0x%x)", GetLastError());
        exit(1);
    }

    size_t size = 0;
    if (!ReadFile(hPipe, &size, sizeof(size_t), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleMutation: failed to read size of mutation buffer (0x%x)", GetLastError());
        exit(1);
    }

    HANDLE hHeap = GetProcessHeap();
    if (hHeap == NULL) {
        LOG_F(ERROR, "handleMutation: failed to get proces heap (0x%x)", GetLastError());
        exit(1);
    }

    BYTE* buf = (BYTE*)HeapAlloc(hHeap, 0, size * sizeof(BYTE));

    if (buf == NULL) {
        LOG_F(ERROR, "handleMutation: failed to allocate mutation buffer (0x%x)", GetLastError());
        exit(1);
    }

    if (!ReadFile(hPipe, buf, (DWORD)size, &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleMutation: failed to read mutation buffer from pipe (0x%x)", GetLastError());
        exit(1);
    }

    if (dwBytesRead < size) {
        LOG_F(WARNING, "handleMutation: read fewer bytes than expected (%d < %lu)", dwBytesRead, size);
        size = dwBytesRead;
    }

    if (size > 0) {
        mutate(buf, size);
    }
    else {
        LOG_F(WARNING, "handleMutation: got an unexpectedly small buffer (%lu < 0), skipping mutation");
    }

    if (!WriteFile(hPipe, buf, (DWORD)size, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "handleMutation: failed to write mutation buffer to pipe (0x%x)", GetLastError());
        exit(1);
    }

    WCHAR targetDir[MAX_PATH + 1] = {0};
    WCHAR targetFile[MAX_PATH + 1] = {0};

    PathCchCombine(targetDir, MAX_PATH, FUZZ_WORKING_PATH, runId_s);
    PathCchCombine(targetFile, MAX_PATH, targetDir, mutate_fname);

    HANDLE hFile = CreateFile(targetFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "handleMutation: failed to create FTK: %S (0x%x)", targetFile, GetLastError());
        exit(1);
    }

    LOG_F(INFO, "calling writeFKT with targetFile: %s", targetFile);

    writeFKT(hFile, type, pathSize, filePath, position, size, buf);

    if (!HeapFree(hHeap, NULL, buf)) {
        LOG_F(ERROR, "handleMutation: failed to deallocate mutation buffer (0x%x)", GetLastError());
        exit(1);
    }

    RpcStringFree((RPC_WSTR *)&runId_s);

    return 0;
}

/* Gets the mutated bytes stored in the FKT file for mutation replay */
DWORD getBytesFKT(HANDLE hFile, BYTE *buf, size_t size)
{
    DWORD dwBytesRead = 0;
    size_t buf_size = 0;

    SetFilePointer(hFile, 0x14, NULL, FILE_BEGIN);
    if (!ReadFile(hFile, &buf_size, 4, &dwBytesRead, NULL)) {
        LOG_F(ERROR, "getBytesFKT: failed to read replay buffer size from FKT (0x%x)", GetLastError());
        exit(1);
    }

    if (buf_size < size) {
        size = buf_size;
    }

    SetFilePointer(hFile, -(LONG)size, NULL, FILE_END);

    if (!ReadFile(hFile, buf, size, &dwBytesRead, NULL)) {
        LOG_F(ERROR, "getBytesFKT: failed to read replay buffer from FKT (0x%x)", GetLastError());
        exit(1);
    }

    LOG_F(INFO, "getBytesFKT: read in %02x %02x %02x %02x %02x %02x %02x %02x\n", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);

    return 0;
}

/* Handles requests over the named pipe from the triage client for replays of mutated bytes */
DWORD handleReplay(HANDLE hPipe)
{
    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;
    UUID runId;
    WCHAR *runId_s;

    if (!ReadFile(hPipe, &runId, sizeof(UUID), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleReplay: failed to read run ID (0x%x)", GetLastError());
        exit(1);
    }

    UuidToString(&runId, (RPC_WSTR *)&runId_s);

    LOG_F(INFO, "Replaying for run id %S", runId_s);

    DWORD mutate_count = 0;
    WCHAR mutate_fname[MAX_PATH + 1] = {0};
    if (!ReadFile(hPipe, &mutate_count, sizeof(DWORD), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleReplay: failed to read mutate count (0x%x)", GetLastError());
        exit(1);
    }

    StringCchPrintfW(mutate_fname, MAX_PATH, FUZZ_RUN_FKT_FMT, mutate_count);

    size_t size = 0;
    if (!ReadFile(hPipe, &size, sizeof(size_t), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleReplay: failed to read size of replay buffer (0x%x)", GetLastError());
        exit(1);
    }

    HANDLE hHeap = GetProcessHeap();

    if (hHeap == NULL) {
        LOG_F(ERROR, "handleReplay: failed to get process heap (0x%x)", GetLastError());
        exit(1);
    }

    BYTE* buf = (BYTE*)HeapAlloc(hHeap, 0, size * sizeof(BYTE));

    if (buf == NULL) {
        LOG_F(ERROR, "handleReplay: failed to allocate replay buffer (0x%x)", GetLastError());
        exit(1);
    }

    WCHAR targetFile[MAX_PATH + 1];
    WCHAR targetDir[MAX_PATH + 1];
    PathCchCombine(targetDir, MAX_PATH, FUZZ_WORKING_PATH, runId_s);
    PathCchCombine(targetFile, MAX_PATH, targetDir, mutate_fname);

    DWORD attrs = GetFileAttributes(targetFile);

    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        LOG_F(ERROR, "handleReplay: missing FKT or is a directory: %S", targetFile);
        exit(1);
    }

    HANDLE hFile = CreateFile(targetFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "handleReplay: failed to open FKT: %S (0x%x)", targetFile, GetLastError());
        exit(1);
    }

    getBytesFKT(hFile, buf, size);

    if (!WriteFile(hPipe, buf, size, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "handleReplay: failed to write replay buffer (0x%x)", GetLastError());
        exit(1);
    }

    if (!CloseHandle(hFile)) {
        LOG_F(ERROR, "handleReplay: failed to close FKT (0x%x)", GetLastError());
        exit(1);
    }

    if (!HeapFree(hHeap, NULL, buf)) {
        LOG_F(ERROR, "handleReplay: failed to deallocate replay buffer (0x%x)", GetLastError());
        exit(1);
    }

    RpcStringFree((RPC_WSTR *)&runId_s);

    return 0;
}

/* Dump information about a given run into the named pipe */
DWORD serveRunInfo(HANDLE hPipe)
{
    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;
    UUID runId;
    WCHAR *runId_s;

    if (!ReadFile(hPipe, &runId, sizeof(UUID), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "serveRunInfo: failed to read run ID (0x%x)", GetLastError());
        exit(1);
    }

    UuidToString(&runId, (RPC_WSTR *)&runId_s);

    WCHAR commandLine[8192] = {0};
    WCHAR targetDir[MAX_PATH + 1] = {0};
    WCHAR targetFile[MAX_PATH + 1] = {0};

    PathCchCombine(targetDir, MAX_PATH, FUZZ_WORKING_PATH, runId_s);
    PathCchCombine(targetFile, MAX_PATH, targetDir, FUZZ_RUN_PROGRAM_TXT);
    HANDLE hFile = CreateFile(targetFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "serveRunInfo: failed to open program.txt: %S (0x%x)", targetFile, GetLastError());
        exit(1);
    }

    if (!ReadFile(hFile, commandLine, 8191 * sizeof(WCHAR), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "serveRunInfo: failed to read program name (0x%x)", GetLastError());
        exit(1);
    }

    if (!CloseHandle(hFile)) {
        LOG_F(ERROR, "serveRunInfo: failed to close program.txt (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(hPipe, &dwBytesRead, sizeof(DWORD), &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "serveRunInfo: failed to write program name size (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(hPipe, commandLine, dwBytesRead, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "serveRunInfo: failed to write program name (0x%x)", GetLastError());
        exit(1);
    }

    ZeroMemory(commandLine, 8192 * sizeof(WCHAR));
    ZeroMemory(targetFile, (MAX_PATH + 1) * sizeof(WCHAR));
    PathCchCombine(targetFile, MAX_PATH, targetDir, FUZZ_RUN_ARGUMENTS_TXT);

    hFile = CreateFile(targetFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "serveRunInfo: failed to open arguments.txt: %S (0x%x)", targetFile, GetLastError());
        exit(1);
    }

    if (!ReadFile(hFile, commandLine, 8191 * sizeof(WCHAR), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "serveRunInfo: failed to read command line argument list (0x%x)", GetLastError());
        exit(1);
    }

    if (!CloseHandle(hFile)) {
        LOG_F(ERROR, "serveRunInfo: failed to close arguments.txt (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(hPipe, &dwBytesRead, sizeof(DWORD), &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "serveRunInfo: failed to write argument list size (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(hPipe, commandLine, dwBytesRead, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "serveRunInfo: faield to write argument list (0x%x)", GetLastError());
        exit(1);
    }

    RpcStringFree((RPC_WSTR *)&runId_s);

    return 0;
}

/* Deletes the run files to free up a Run ID if the last run didn't find a crash */
DWORD finalizeRun(HANDLE hPipe)
{
    DWORD dwBytesRead = 0;
    UUID runId;
    WCHAR *runId_s;

    if (!ReadFile(hPipe, &runId, sizeof(UUID), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "finalizeRun: failed to read run ID (0x%x)", GetLastError());
        exit(1);
    }

    UuidToString(&runId, (RPC_WSTR *)&runId_s);

    BOOL crash = false;
    if (!ReadFile(hPipe, &crash, sizeof(BOOL), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "finalizeRun: failed to read crash status (0x%x)", GetLastError());
        exit(1);
    }

    BOOL remove = true;
    if (!ReadFile(hPipe, &remove, sizeof(BOOL), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "finalizeRun: failed to read remove flag (0x%x)", GetLastError());
        exit(1);
    }

    LOG_F(INFO, "finalizeRun: finalizing %S", runId_s);

    if (!crash && remove) {
        LOG_F(INFO, "finalizeRun: no crash, removing run %S", runId_s);
        EnterCriticalSection(&critId);

        WCHAR targetDir[MAX_PATH + 1] = {0};
        PathCchCombine(targetDir, MAX_PATH, FUZZ_WORKING_PATH, runId_s);

        SHFILEOPSTRUCT remove_op = {
            NULL,
            FO_DELETE,
            targetDir,
            L"",
            FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT,
            false,
            NULL,
            L""
        };

        SHFileOperation(&remove_op);
        LeaveCriticalSection(&critId);
    }
    else if (!crash && !remove) {
        LOG_F(INFO, "finalizeRun: no crash, but not removing files (requested)");
    }
    else {
        LOG_F(INFO, "finalizeRun: crash found for run %S", runId_s);
    }

    RpcStringFree((RPC_WSTR *)&runId_s);

    return 0;
}

/* Return the location of the crash.json file for a given run ID */
DWORD crashPath(HANDLE hPipe)
{
    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;
    UUID runId;
    WCHAR *runId_s;

    if (!ReadFile(hPipe, &runId, sizeof(UUID), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "crashPath: failed to read UUID (0x%x)", GetLastError());
        exit(1);
    }

    UuidToString(&runId, (RPC_WSTR *)&runId_s);

    WCHAR targetDir[MAX_PATH + 1] = {0};
    WCHAR targetFile[MAX_PATH + 1] = {0};

    PathCchCombine(targetDir, MAX_PATH, FUZZ_WORKING_PATH, runId_s);
    PathCchCombine(targetFile, MAX_PATH, targetDir, FUZZ_RUN_CRASH_JSON);

    size_t size = (wcslen(targetFile) + 1) * sizeof(WCHAR);

    if (!WriteFile(hPipe, &targetFile, (DWORD)size, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "crashPath: failed to write crash.json path to pipe (0x%x)", GetLastError());
        exit(1);
    }

    RpcStringFree((RPC_WSTR *)&runId_s);

    return 0;
}

/* Handles incoming connections from clients */
DWORD WINAPI threadHandler(LPVOID lpvPipe)
{
    HANDLE hPipe = (HANDLE)lpvPipe;

    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;

    BYTE eventId = 255;

    // NOTE(ww): This is a second event loop, inside of the infinite event loop that
    // creates each thread and calls threadHandler. We do this so that clients can
    // re-use their pipe instances to send multiple events -- with only the top-level
    // loop, each connection would be discarded after a single event.
    //
    // To end a "session", a client sends the EVT_SESSION_TEARDOWN event. "Session"
    // is in scare quotes because each session is essentially anonymous -- the server
    // only sees when they end, not which runs or events they correspond to.
    do {
        if (!ReadFile(hPipe, &eventId, sizeof(BYTE), &dwBytesRead, NULL)) {
            if (GetLastError() != ERROR_BROKEN_PIPE){
                LOG_F(ERROR, "threadHandler: failed to read eventId (0x%x)", GetLastError());
                exit(1);
            }
            else{
                 // Pipe was broken when we tried to read it. Happens when the python client
                 // checks if it exists.
                return 0;
            }
        }

        LOG_F(INFO, "threadHandler: got event ID: %d", eventId);

        // Dispatch individual requests based on which event the client requested
        switch (eventId) {
            case EVT_RUN_ID:
                generateRunId(hPipe);
                break;
            case EVT_MUTATION:
                handleMutation(hPipe);
                break;
            case EVT_REPLAY:
                handleReplay(hPipe);
                break;
            case EVT_RUN_INFO:
                serveRunInfo(hPipe);
                break;
            case EVT_RUN_COMPLETE:
                finalizeRun(hPipe);
                break;
            case EVT_CRASH_PATH:
                crashPath(hPipe);
                break;
            case EVT_SESSION_TEARDOWN:
                LOG_F(INFO, "Ending a client's session with the server.");
                break;
            default:
                LOG_F(ERROR, "Unknown or invalid event id 0x%x", eventId);
                break;
        }
    } while (eventId != EVT_SESSION_TEARDOWN);

    if (!FlushFileBuffers(hPipe)) {
        LOG_F(ERROR, "threadHandler: failed to flush pipe (0x%x)", GetLastError());
        exit(1);
    }

    if (!DisconnectNamedPipe(hPipe)) {
        LOG_F(ERROR, "threadHandler: failed to disconnect pipe (0x%x)", GetLastError());
        exit(1);
    }

    if (!CloseHandle(hPipe)) {
        LOG_F(ERROR, "threadHandler: failed to close pipe (0x%x)", GetLastError());
        exit(1);
    }

    return 0;
}

/* concurrency protection */
void lockProcess()
{
    hProcessMutex = CreateMutex(NULL, FALSE, L"fuzz_server_mutex");
    if (!hProcessMutex || hProcessMutex == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "lockProcess: could not get process lock (handle)");
        exit(1);
    }

    DWORD result = WaitForSingleObject(hProcessMutex, 0);
    if (result != WAIT_OBJECT_0) {
        LOG_F(ERROR, "lockProcess: could not get process lock (lock)");
        exit(1);
    }
}

// Init dirs and create a new thread to handle input from the named pipe
int main(int mArgc, char **mArgv)
{
    initLoggingFile();
    loguru::init(mArgc, mArgv);
    CHAR logLocalPathA[MAX_PATH]= {0};
    size_t converted;
    wcstombs_s(&converted, logLocalPathA, MAX_PATH - 1, FUZZ_LOG, MAX_PATH - 1);
    loguru::add_file(logLocalPathA, loguru::Append, loguru::Verbosity_MAX);

    std::atexit(server_cleanup);

    initWorkingDir();

    LOG_F(INFO, "main: server started!");

    lockProcess();

    InitializeCriticalSection(&critId);

    while (1) {
        HANDLE hPipe = CreateNamedPipe(
            FUZZ_SERVER_PATH,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            BUFSIZ,
            BUFSIZ,
            0,
            NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            LOG_F(ERROR, "main: could not create pipe");
            return 1;
        }

        BOOL connected = ConnectNamedPipe(hPipe, NULL) ?
            TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (connected) {
            DWORD threadID;
            HANDLE hThread = CreateThread(
                NULL,
                0,
                threadHandler,
                (LPVOID)hPipe,
                0,
                &threadID);

            if (hThread == NULL)
            {
                LOG_F(ERROR, "main: CreateThread failed (0x%x)\n", GetLastError());
                return -1;
            }
            else {
                CloseHandle(hThread);
            }
        }
        else {
            LOG_F(ERROR, "main: could not connect to hPipe");
            CloseHandle(hPipe);
        }
    }

    return 0;
}
