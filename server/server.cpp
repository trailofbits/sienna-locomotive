#include <random>
#define NOMINMAX
#include <Windows.h>
#include <set>
#include <map>
#include <unordered_map>

#define LOGURU_IMPLEMENTATION 1
#include "loguru.hpp"

#define BUFSIZE 100000

#include <ShlObj.h>
#include <PathCch.h>
#pragma comment(lib, "Pathcch.lib")

CRITICAL_SECTION critId;
CRITICAL_SECTION critLog;

HANDLE hLog = INVALID_HANDLE_VALUE;

WCHAR FUZZ_WORKING_STAR[MAX_PATH] = L"";
WCHAR FUZZ_WORKING_FMT[MAX_PATH] = L"";
WCHAR FUZZ_WORKING_FMT_PROGRAM[MAX_PATH] = L"";
WCHAR FUZZ_WORKING_FMT_ARGS[MAX_PATH] = L"";
WCHAR FUZZ_WORKING_FMT_FKT[MAX_PATH] = L"";
WCHAR FUZZ_WORKING_FMT_STAR[MAX_PATH] = L"";
WCHAR FUZZ_WORKING_FMT_FMT[MAX_PATH] = L"";
WCHAR FUZZ_WORKING_FMT_EXECUTION[MAX_PATH] = L"";
WCHAR FUZZ_WORKING_FMT_MEM[MAX_PATH] = L"";
WCHAR FUZZ_WORKING_FMT_CRASH[MAX_PATH] = L"";
WCHAR FUZZ_WORKING_FMT_JSON[MAX_PATH] = L"";
WCHAR FUZZ_LOG[MAX_PATH] = L"";

// Initialize global variables containing relevant file/folder paths
VOID initDirs() {
    PWSTR roamingPath;
    SHGetKnownFolderPath(FOLDERID_RoamingAppData, NULL, NULL, &roamingPath);
    WCHAR workingLocalPath[MAX_PATH] = L"Trail of Bits\\fuzzkit\\working";
    WCHAR combinedPath[MAX_PATH] = L"";
    PathCchCombine(combinedPath, MAX_PATH, roamingPath, workingLocalPath);

    PathCchCombine(FUZZ_WORKING_STAR, MAX_PATH, combinedPath, L"*");
    PathCchCombine(FUZZ_WORKING_FMT, MAX_PATH, combinedPath, L"%d");
    PathCchCombine(FUZZ_WORKING_FMT_PROGRAM, MAX_PATH, FUZZ_WORKING_FMT, L"program.txt");
    PathCchCombine(FUZZ_WORKING_FMT_ARGS, MAX_PATH, FUZZ_WORKING_FMT, L"arguments.txt");
    PathCchCombine(FUZZ_WORKING_FMT_FKT, MAX_PATH, FUZZ_WORKING_FMT, L"%d.fkt");
    PathCchCombine(FUZZ_WORKING_FMT_STAR, MAX_PATH, FUZZ_WORKING_FMT, L"*");
    PathCchCombine(FUZZ_WORKING_FMT_FMT, MAX_PATH, FUZZ_WORKING_FMT, L"%s");
    PathCchCombine(FUZZ_WORKING_FMT_EXECUTION, MAX_PATH, FUZZ_WORKING_FMT, L"execution.trc");
    PathCchCombine(FUZZ_WORKING_FMT_MEM, MAX_PATH, FUZZ_WORKING_FMT, L"mem.dmp");
    PathCchCombine(FUZZ_WORKING_FMT_CRASH, MAX_PATH, FUZZ_WORKING_FMT, L"execution.csh");
    PathCchCombine(FUZZ_WORKING_FMT_JSON, MAX_PATH, FUZZ_WORKING_FMT, L"crash.json");

    SHGetKnownFolderPath(FOLDERID_RoamingAppData, NULL, NULL, &roamingPath);
    WCHAR logLocalPath[MAX_PATH] = L"Trail of Bits\\fuzzkit\\log\\server.log";
    PathCchCombine(FUZZ_LOG, MAX_PATH, roamingPath, logLocalPath);

    CoTaskMemFree(roamingPath);
}

/* Checks the working directory and finds a new unique run ID for the current fuzzing run */
DWORD findUnusedId() {
    HANDLE hFind;
    WIN32_FIND_DATA findData;
    std::set<UINT64> usedIds;

    EnterCriticalSection(&critId);

    hFind = FindFirstFile(FUZZ_WORKING_STAR, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.cFileName[0] >= 0x30 && findData.cFileName[0] <= 0x39) {
                UINT64 runId = wcstoul(findData.cFileName, NULL, 0);
                usedIds.insert(runId);
            }
        } while (FindNextFile(hFind, &findData));
        FindClose(hFind);
    }

    DWORD id = 0;
    for (id = 0; id <= UINT64_MAX; id++) {
        if (usedIds.find(id) == usedIds.end()) {
            LOG_F(INFO, "Found run id 0x%x", id);
            break;
        }
    }

    WCHAR targetDir[MAX_PATH];
    wsprintf(targetDir, FUZZ_WORKING_FMT, id);
    if(!CreateDirectory(targetDir, NULL)) {
        LOG_F(ERROR, "FindUnusedId (0x%x)", GetLastError());
        exit(1);
    }

    LeaveCriticalSection(&critId);

    return id;
}

/* Calls findUnusedId to get a new run ID, writes relevant run metadata files into the corresponding run metadata dir
    This, like many things in the server, is pretty overzealous about exiting after any errors, often without an
    explanation of what happened. TODO - fix this */
DWORD generateRunId(HANDLE hPipe) {
    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;

    LOG_F(INFO, "Run id requested");
    DWORD runId = findUnusedId();

    BOOL success = WriteFile(hPipe, &runId, sizeof(DWORD), &dwBytesWritten, NULL);

    // get program name
    TCHAR commandLine[8192] = { 0 };
    DWORD size = 0;
    if(!ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "GenerateRunId (0x%x)", GetLastError());
        exit(1);
    }

    if (size > 8191) {
        LOG_F(ERROR, "Invalid size for command name");
        return 1;
    }

    if(!ReadFile(hPipe, commandLine, size, &dwBytesRead, NULL)) {
        LOG_F(ERROR, "GenerateRunId (0x%x)", GetLastError());
        exit(1);
    }

    WCHAR targetFile[MAX_PATH + 1] = { 0 };
    wsprintf(targetFile, FUZZ_WORKING_FMT_PROGRAM, runId);
    HANDLE hFile = CreateFile(targetFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    if(hFile == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "GenerateRunId (0x%x)", GetLastError());
        exit(1);
    }

    if(!WriteFile(hFile, commandLine, size, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "GenerateRunId (0x%x)", GetLastError());
        exit(1);
    }

    if(!CloseHandle(hFile)) {
        LOG_F(ERROR, "GenerateRunId (0x%x)", GetLastError());
        exit(1);
    }

    ZeroMemory(commandLine, 8192 * sizeof(TCHAR));

    // get program arguments
    size = 0;
    if(!ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "GenerateRunId (0x%x)", GetLastError());
        exit(1);
    }

    if (size > 8191) {
        LOG_F(ERROR, "Invalid size for command name");
        return 1;
    }

    if(!ReadFile(hPipe, commandLine, size, &dwBytesRead, NULL)) {
        LOG_F(ERROR, "GenerateRunId (0x%x)", GetLastError());
        exit(1);
    }

    ZeroMemory(targetFile, (MAX_PATH + 1)*sizeof(WCHAR));
    wsprintf(targetFile, FUZZ_WORKING_FMT_ARGS, runId);
    hFile = CreateFile(targetFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    if(hFile == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "GenerateRunId (0x%x)", GetLastError());
        exit(1);
    }

    if(!WriteFile(hFile, commandLine, size, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "GenerateRunId (0x%x)", GetLastError());
        exit(1);
    }

    if(!CloseHandle(hFile)) {
        LOG_F(ERROR, "GenerateRunId (0x%x)", GetLastError());
        exit(1);
    }

    return 0;
}

/*
  Mutation strategies. The server selects one each time the fuzzing harness requests mutated bytes
*/

DWORD getRand() {
    DWORD random = rand();
    random <<= 15;
    random |= rand();

    return random;
}

VOID strategyAAAA(BYTE *buf, DWORD size) {
    for (DWORD i = 0; i < size; i++) {
        buf[i] = 'A';
    }
}

VOID strategyFlipBit(BYTE *buf, DWORD size) {
    std::random_device rd;
    srand(rd());

    DWORD pos = getRand() % size;
    BYTE byte = buf[pos];

    BYTE mask = 1 << rand() % 8;
    buf[pos] = byte ^ mask;
}

VOID strategyRepeatBytes(BYTE *buf, DWORD size) {
    std::random_device rd;
    srand(rd());

    // pos -> zero to second to last byte
    DWORD pos = getRand() % (size - 1);

    // repeat_length -> 1 to (remaining_size - 1)
    DWORD size_m2 = size - 2;
    DWORD repeat_length = 0;
    if(size_m2 > pos) {
        repeat_length = getRand() % (size_m2 - pos);
    }
    repeat_length++;

    // set start and end
    DWORD curr_pos = pos + repeat_length;
    DWORD end = getRand() % (size - curr_pos);
    end += curr_pos + 1;

    while(curr_pos < end) {
        buf[curr_pos] = buf[pos];
        curr_pos++;
        pos++;
    }
}

VOID strategyRepeatBytesBackward(BYTE *buf, DWORD size) {
    std::random_device rd;
    srand(rd());

    // pos -> 1 to last byte
    DWORD pos = getRand() % (size - 1);
    pos++;

    // repeat_length -> 1 to pos
    DWORD repeat_length = getRand() % pos;
    repeat_length++;

    // set start
    INT curr_pos = pos - repeat_length;

    // set end between 0 to (curr_pos + 1)
    INT end = getRand() % (curr_pos + 1);

    // gte so we can go to 0
    while(curr_pos >= end) {
        buf[curr_pos] = buf[pos];
        curr_pos--;
        pos--;
    }
}

VOID strategyDeleteBytes(BYTE *buf, DWORD size) {
    std::random_device rd;
    srand(rd());

    // pos -> zero to second to last byte
    DWORD pos = 0;
    if(size > 1) {
        getRand() % (size - 1);
    }

    // delete_length -> 1 to (remaining_size - 1)
    DWORD size_m2 = size - 2;
    DWORD delete_length = 0;
    if(size_m2 > pos) {
        delete_length = getRand() % (size_m2 - pos);
    }
    delete_length++;

    for(DWORD i=0; i<delete_length; i++) {
        buf[pos+i] = 0;
    }
}

VOID strategyRandValues(BYTE *buf, DWORD size) {
    std::random_device rd;
    srand(rd());

    DWORD rand_size = 0;
    INT max = 0;
    while(max < 1) {
        // rand_size -> 1, 2, 4, 8
        rand_size = pow(2, getRand() % 4);
        max = (size + 1);
        max -= rand_size;
    }

    // pos -> zero to ((size + 1) - rand_size)
    // e.g. buf size is 16, rand_size is 8
    // max will be from 0 to 9 guanteeing a
    // pos that will fit into the buffer
    DWORD pos = getRand() % max;

    for(DWORD i=0; i<rand_size; i++) {
        BYTE mut = rand() % 256;
        buf[pos + i] = mut;
    }
}

#define VALUES1 -128, -2, -1, 0, 1, 2, 4, 8, 10, 16, 32, 64, 100, 127, 128, 255
#define VALUES2 -32768, -129, 256, 512, 1000, 1024, 4096, 32767, 65535
#define VALUES4 -2147483648, -100663046, -32769, 32768, 65536, 100663045, 2147483647, 4294967295
#define VALUES8  -9151314442816848000, -2147483649, 2147483648, 4294967296, 432345564227567365, 18446744073709551615

VOID strategyKnownValues(BYTE *buf, DWORD size) {
    UINT8 values1[] = { VALUES1 };
    UINT16 values2[] = { VALUES1, VALUES2 };
    UINT32 values4[] = { VALUES1, VALUES2, VALUES4 };
    UINT64 values8[] = { VALUES1, VALUES2, VALUES4, VALUES8 };

    std::random_device rd;
    srand(rd());

    DWORD rand_size = 0;
    INT max = 0;
    while(max < 1) {
        // size -> 1, 2, 4, 8
        rand_size = pow(2, getRand() % 4);
        max = (size + 1);
        max -= rand_size;
    }

    // pos -> zero to ((size + 1) - rand_size)
    // e.g. buf size is 16, rand_size is 8
    // max will be from 0 to 9 guaranteeing a
    // pos that will fit into the buffer
    DWORD pos = getRand() % max;
    BOOL endian = rand() % 2;

    DWORD selection = 0;
    switch(rand_size) {
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

VOID strategyAddSubKnownValues(BYTE *buf, DWORD size) {
    UINT8 values1[] = { VALUES1 };
    UINT16 values2[] = { VALUES1, VALUES2 };
    UINT32 values4[] = { VALUES1, VALUES2, VALUES4 };
    UINT64 values8[] = { VALUES1, VALUES2, VALUES4, VALUES8 };

    std::random_device rd;
    srand(rd());

    DWORD rand_size = 0;
    DWORD max = 0;
    while(max < 1) {
        // size -> 1, 2, 4, 8
        rand_size = pow(2, getRand() % 4);
        max = (size + 1) - rand_size;
    }

    // pos -> zero to ((size + 1) - rand_size)
    // e.g. buf size is 16, rand_size is 8
    // max will be from 0 to 9 guaranteeing a
    // pos that will fit into the buffer
    DWORD pos = getRand() % max;
    BOOL endian = rand() % 2;

    BYTE sub = 1;
    if(rand() % 2) {
        sub = -1;
    }

    DWORD selection = 0;
    switch(rand_size) {
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

VOID strategyEndianSwap(BYTE *buf, DWORD size) {
    std::random_device rd;
    srand(rd());

    DWORD rand_size = 0;
    DWORD max = 0;
    while(max < 1) {
        // size -> 1, 2, 4, 8
        rand_size = pow(2, getRand() % 4);
        max = (size + 1) - rand_size;
    }

    // pos -> zero to ((size + 1) - rand_size)
    // e.g. buf size is 16, rand_size is 8
    // max will be from 0 to 9 guaranteeing a
    // pos that will fit into the buffer
    DWORD pos = getRand() % max;

    switch(rand_size) {
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
DWORD mutate(BYTE *buf, DWORD size) {
    // afl for inspiration
    if(size == 0) {
        return 0;
    }

    std::random_device rd;
    srand(rd());

    DWORD choice = getRand() % 8;
    switch(choice) {
        case 0:
            LOG_F(INFO, "strategyFlipBit");
            strategyFlipBit(buf, size);
            break;
        case 1:
            LOG_F(INFO, "strategyRandValues");
            strategyRandValues(buf, size);
            break;
        case 2:
            LOG_F(INFO, "strategyRepeatBytes");
            strategyRepeatBytes(buf, size);
            break;
        case 3:
            LOG_F(INFO, "strategyKnownValues");
            strategyKnownValues(buf, size);
            break;
        case 4:
            LOG_F(INFO, "strategyAddSubKnownValues");
            strategyAddSubKnownValues(buf, size);
            break;
        case 5:
            LOG_F(INFO, "strategyEndianSwap");
            strategyEndianSwap(buf, size);
            break;
        case 6:
            LOG_F(INFO, "strategyDeleteBytes");
            strategyDeleteBytes(buf, size);
            break;
        case 7:
            LOG_F(INFO, "strategyRepeatBytesBackward");
            strategyRepeatBytesBackward(buf, size);
            break;
        default:
            strategyAAAA(buf, size);
            break;
    }

    // insert bytes
        // move bytes
        // add random bytes to space

    return 0;
}

/* Writes the fkt file in the event we found a crash. Stores information about the mutation that caused it */
DWORD writeFKT(HANDLE hFile, DWORD type, DWORD pathSize, TCHAR *filePath, DWORD64 position, DWORD size, BYTE* buf) {
    DWORD dwBytesWritten = 0;

    if (!WriteFile(hFile, "FKT\0", 4, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
        exit(1);
    }

    // only one type for right now, files
    if (!WriteFile(hFile, &type, sizeof(DWORD), &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(hFile, &pathSize, sizeof(DWORD), &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(hFile, filePath, pathSize * sizeof(TCHAR), &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(hFile, &position, sizeof(DWORD64), &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(hFile, &size, sizeof(DWORD), &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(hFile, buf, size, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
        exit(1);
    }

    if (!CloseHandle(hFile)) {
        LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
        exit(1);
    }

    return 0;
}

/* handles mutation requests over the named pipe from the fuzzing harness */
DWORD handleMutation(HANDLE hPipe) {
    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;

    DWORD runId = 0;
    if(!ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
        exit(1);
    }

    DWORD type = 0;
    if(!ReadFile(hPipe, &type, sizeof(DWORD), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
        exit(1);
    }

    DWORD mutateCount = 0;
    if(!ReadFile(hPipe, &mutateCount, sizeof(DWORD), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
        exit(1);
    }

    DWORD pathSize = 0;
    if (!ReadFile(hPipe, &pathSize, sizeof(DWORD), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
        exit(1);
    }

    if (pathSize > MAX_PATH) {
        LOG_F(ERROR, "HandleMutation MAX_PATH", GetLastError());
        exit(1);
    }

    TCHAR filePath[MAX_PATH + 1];
    if (!ReadFile(hPipe, &filePath, pathSize * sizeof(TCHAR), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
        exit(1);
    }

    filePath[pathSize] = 0;
    LOG_F(INFO, "file path: %s\n", filePath);

    DWORD64 position = 0;
    if (!ReadFile(hPipe, &position, sizeof(DWORD64), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
        exit(1);
    }

    DWORD size = 0;
    if(!ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
        exit(1);
    }

    HANDLE hHeap = GetProcessHeap();
    if(hHeap == NULL) {
        LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
        exit(1);
    }

    BYTE* buf = (BYTE*)HeapAlloc(hHeap, 0, size * sizeof(BYTE));

    if(buf == NULL) {
        LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
        exit(1);
    }

    if(!ReadFile(hPipe, buf, size, &dwBytesRead, NULL)) {
        LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
        exit(1);
    }

    if (dwBytesRead != size) {
        size = dwBytesRead;
    }

    if(size > 0)
        mutate(buf, size);

    if(!WriteFile(hPipe, buf, size, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
        exit(1);
    }

    WCHAR targetFile[MAX_PATH+1];
    wsprintf(targetFile, FUZZ_WORKING_FMT_FKT, runId, mutateCount);
    HANDLE hFile = CreateFile(targetFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    if(hFile == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
        exit(1);
    }

    writeFKT(hFile, type, pathSize, filePath, position, size, buf);

    if(!HeapFree(hHeap, NULL, buf)) {
        LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
        exit(1);
    }

    return 0;
}

/* Gets the mutated bytes stored in the FKT file for mutation replay */
DWORD getBytesFKT(HANDLE hFile, BYTE *buf, DWORD size) {
    DWORD dwBytesRead = 0;

    DWORD buf_size = 0;
    SetFilePointer(hFile, 0x14, NULL, FILE_BEGIN);
    if (!ReadFile(hFile, &buf_size, 4, &dwBytesRead, NULL)) {
        LOG_F(ERROR, "HandleReplay (0x%x)", GetLastError());
        exit(1);
    }

    if(buf_size < size) {
        size = buf_size;
    }

    SetFilePointer(hFile, -(LONG)size, NULL, FILE_END);

    if (!ReadFile(hFile, buf, size, &dwBytesRead, NULL)) {
        LOG_F(ERROR, "HandleReplay (0x%x)", GetLastError());
        exit(1);
    }

    LOG_F(INFO, "Read in %02x %02x %02x %02x %02x %02x %02x %02x\n", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);

    return 0;
}

/* Handles requests over the named pipe from the triage client for replays of mutated bytes */
DWORD handleReplay(HANDLE hPipe) {
    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;

    DWORD runId = 0;
    if(!ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "HandleReplay (0x%x)", GetLastError());
        exit(1);
    }

    LOG_F(INFO, "Replaying for run id %d", runId);

    DWORD mutateCount = 0;

    if(!ReadFile(hPipe, &mutateCount, sizeof(DWORD), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "HandleReplay (0x%x)", GetLastError());
        exit(1);
    }

    DWORD size = 0;
    if(!ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "HandleReplay (0x%x)", GetLastError());
        exit(1);
    }

    HANDLE hHeap = GetProcessHeap();

    if(hHeap == NULL) {
        LOG_F(ERROR, "HandleReplay (0x%x)", GetLastError());
        exit(1);
    }

    BYTE* buf = (BYTE*)HeapAlloc(hHeap, 0, size * sizeof(BYTE));

    if(buf == NULL) {
        LOG_F(ERROR, "HandleReplay (0x%x)", GetLastError());
        exit(1);
    }

    WCHAR targetFile[MAX_PATH + 1];
    wsprintf(targetFile, FUZZ_WORKING_FMT_FKT, runId, mutateCount);
    // TODO: validate file exists
    HANDLE hFile = CreateFile(targetFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

    if(hFile == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "HandleReplay (0x%x)", GetLastError());
        exit(1);
    }

    getBytesFKT(hFile, buf, size);

    if(!WriteFile(hPipe, buf, size, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "HandleReplay (0x%x)", GetLastError());
        exit(1);
    }

    if(!CloseHandle(hFile)) {
        LOG_F(ERROR, "HandleReplay (0x%x)", GetLastError());
        exit(1);
    }

    if(!HeapFree(hHeap, NULL, buf)) {
        LOG_F(ERROR, "HandleReplay (0x%x)", GetLastError());
        exit(1);
    }

    return 0;
}

/* Dump information about a given run into the named pipe */
DWORD serveRunInfo(HANDLE hPipe) {
    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;

    DWORD runId = 0;
    if(!ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
        exit(1);
    }

    TCHAR commandLine[8192] = { 0 };
    WCHAR targetFile[MAX_PATH + 1] = { 0 };

    wsprintf(targetFile, FUZZ_WORKING_FMT_PROGRAM, runId);
    HANDLE hFile = CreateFile(targetFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

    if(hFile == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
        exit(1);
    }

    if(!ReadFile(hFile, commandLine, 8191 * sizeof(TCHAR), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
        exit(1);
    }

    if(!CloseHandle(hFile)) {
        LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
        exit(1);
    }

    if(!WriteFile(hPipe, &dwBytesRead, sizeof(DWORD), &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
        exit(1);
    }

    if(!WriteFile(hPipe, commandLine, dwBytesRead, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
        exit(1);
    }

    ZeroMemory(commandLine, 8192 * sizeof(TCHAR));
    ZeroMemory(targetFile, (MAX_PATH + 1) * sizeof(WCHAR));
    wsprintf(targetFile, FUZZ_WORKING_FMT_ARGS, runId);

    hFile = CreateFile(targetFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

    if(hFile == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
        exit(1);
    }

    if(!ReadFile(hFile, commandLine, 8191 * sizeof(TCHAR), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
        exit(1);
    }

    if(!CloseHandle(hFile)) {
        LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
        exit(1);
    }

    if(!WriteFile(hPipe, &dwBytesRead, sizeof(DWORD), &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
        exit(1);
    }

    if(!WriteFile(hPipe, commandLine, dwBytesRead, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
        exit(1);
    }

    return 0;
}

/* Deletes the run files to free up a Run ID if the last run didn't find a crash */
DWORD finalizeRun(HANDLE hPipe) {
    DWORD dwBytesRead = 0;

    DWORD runId = 0;
    if(!ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "FinalizeRun (0x%x)", GetLastError());
        exit(1);
    }

    BOOL crash = false;
    if(!ReadFile(hPipe, &crash, sizeof(BOOL), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "FinalizeRun (0x%x)", GetLastError());
        exit(1);
    }
    LOG_F(INFO, "Finalizing run 0x%x", runId);

    if (!crash) {
        LOG_F(INFO, "No crash removing run 0x%x", runId);
        EnterCriticalSection(&critId);
        WIN32_FIND_DATA findData;
        WCHAR targetFile[MAX_PATH + 1] = { 0 };
        wsprintf(targetFile, FUZZ_WORKING_FMT_STAR, runId);

        // empty directory
        HANDLE hFind = FindFirstFile(targetFile, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                // TODO: this will fail on directories, but we don't have any directories yet
                wsprintf(targetFile, FUZZ_WORKING_FMT_FMT, runId, findData.cFileName);
                DeleteFile(targetFile);
            } while (FindNextFile(hFind, &findData));
            FindClose(hFind);
        }

        wsprintf(targetFile, FUZZ_WORKING_FMT, runId);
        if(!RemoveDirectory(targetFile)) {
            LOG_F(ERROR, "FinalizeRun (0x%x)", GetLastError());
            exit(1);
        }

        LeaveCriticalSection(&critId);
    }
    else {
        LOG_F(INFO, "Crash found for run 0x%x", runId);
    }

    return 0;
}

/* Return the location of the crash.json file for a given run ID */
DWORD crashPath(HANDLE hPipe) {
    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;

    DWORD runId = 0;
    if(!ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "crashPath (0x%x)", GetLastError());
        exit(1);
    }

    WCHAR targetFile[MAX_PATH + 1] = { 0 };
    int len = wsprintf(targetFile, FUZZ_WORKING_FMT_JSON, runId);
    DWORD size = (wcslen(targetFile) + 1) * sizeof(WCHAR);

    if(!WriteFile(hPipe, &targetFile, size, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "crashPath (0x%x)", GetLastError());
        exit(1);
    }

    return 0;
}

// TODO: check then delete all the tracing stuff
enum Event {
    EVT_RUN_ID,             // 0
    EVT_MUTATION,           // 1
    EVT_REPLAY,             // 2
    EVT_RUN_INFO,           // 3
    EVT_RUN_COMPLETE,       // 4
    EVT_CRASH_PATH,         // 5
};

/* Handles incoming connections from clients */
DWORD WINAPI threadHandler(LPVOID lpvPipe) {
    HANDLE hPipe = (HANDLE)lpvPipe;

    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;

    BYTE eventId = 255;
    if(!ReadFile(hPipe, &eventId, sizeof(BYTE), &dwBytesRead, NULL)) {
        if (GetLastError() != ERROR_BROKEN_PIPE){
            LOG_F(ERROR, "ThreadHandler (0x%x)", GetLastError());
            exit(1);
        }
        else{
             // Pipe was broken when we tried to read it. Happens when the python client
             // checks if it exists.
            return 0;
        }
    }

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
        default:
            LOG_F(ERROR, "Unknown or invalid event id 0x%x", eventId);
            break;
    }

    if(!FlushFileBuffers(hPipe)) {
        LOG_F(ERROR, "ThreadHandler (0x%x)", GetLastError());
        exit(1);
    }

    if(!DisconnectNamedPipe(hPipe)) {
        LOG_F(ERROR, "ThreadHandler (0x%x)", GetLastError());
        exit(1);
    }

    if(!CloseHandle(hPipe)) {
        LOG_F(ERROR, "ThreadHandler (0x%x)", GetLastError());
        exit(1);
    }

    return 0;
}

HANDLE hProcessMutex = INVALID_HANDLE_VALUE;

/* concurrency protection */
void lockProcess() {
    hProcessMutex = CreateMutex(NULL, FALSE, L"fuzz_server_mutex");
    if(!hProcessMutex || hProcessMutex == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "Could not get process lock (handle)");
        exit(1);
    }

    DWORD result = WaitForSingleObject(hProcessMutex, 0);
    if(result != WAIT_OBJECT_0) {
        LOG_F(ERROR, "Could not get process lock (lock)");
        exit(1);
    }
}

// Init dirs and create a new thread to handle input from the named pipe
int main(int mArgc, char **mArgv)
{
    initDirs();

    loguru::init(mArgc, mArgv);
    CHAR logLocalPathA[MAX_PATH];
    wcstombs(logLocalPathA, FUZZ_LOG, MAX_PATH);
    loguru::add_file(logLocalPathA, loguru::Append, loguru::Verbosity_MAX);

    LOG_F(INFO, "Server started!");

    lockProcess();

    InitializeCriticalSection(&critId);
    InitializeCriticalSection(&critLog);

    while (1) {
        DWORD outSize = BUFSIZE;
        DWORD inSize = BUFSIZE;
        HANDLE hPipe = CreateNamedPipe(
            L"\\\\.\\pipe\\fuzz_server",
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            outSize,
            inSize,
            0,
            NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            LOG_F(ERROR, "Could not create pipe");
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
                LOG_F(ERROR, "CreateThread (0x%x)\n", GetLastError());
                return -1;
            }
            else {
                CloseHandle(hThread);
            }
        }
        else {
            LOG_F(ERROR, "Could not connect to hPipe");
            CloseHandle(hPipe);
        }
    }

    // TODO: stop gracefully?
    ReleaseMutex(hProcessMutex);
    CloseHandle(hProcessMutex);
    DeleteCriticalSection(&critId);
    DeleteCriticalSection(&critLog);
    return 0;
}
