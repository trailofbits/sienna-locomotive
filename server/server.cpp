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
#include "vendor/loguru.hpp"

#include "server.hpp"

static CRITICAL_SECTION critId;
static HANDLE hProcessMutex = INVALID_HANDLE_VALUE;

static HANDLE hLog = INVALID_HANDLE_VALUE;

static wchar_t FUZZ_WORKING_PATH[MAX_PATH] = L"";
static wchar_t FUZZ_ARENAS_PATH[MAX_PATH] = L"";
static wchar_t FUZZ_LOG[MAX_PATH] = L"";

/*
    TODO(ww): Create a formal server API. Doing so will help with:
        1. all of the `exit`s scattered through the current code
        2. iterating on the server protocol without breaking clients
*/


// Called on process termination (by atexit).
static void server_cleanup()
{
    LOG_F(INFO, "server_cleanup: Called, cleaning things up");

    // NOTE(ww): We could probably check return codes here, but there's
    // no point -- the process is about to be destroyed anyways.
    ReleaseMutex(hProcessMutex);
    CloseHandle(hProcessMutex);
    DeleteCriticalSection(&critId);
}

// Initialize the global variable (FUZZ_LOG) containing the path to the logging file.
// NOTE(ww): We separate this from initWorkingDirs so that we can log any errors that
// happen to occur in initWorkingDirs.
void initLoggingFile() {
    wchar_t *roamingPath;
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
void initWorkingDirs() {
    wchar_t *roamingPath;
    SHGetKnownFolderPath(FOLDERID_RoamingAppData, NULL, NULL, &roamingPath);
    wchar_t runsLocalPath[MAX_PATH] = L"Trail of Bits\\fuzzkit\\runs";

    if (PathCchCombine(FUZZ_WORKING_PATH, MAX_PATH, roamingPath, runsLocalPath) != S_OK) {
        LOG_F(ERROR, "initWorkingDirs: failed to combine working dir path (0x%x)", GetLastError());
        exit(1);
    }

    wchar_t arenasLocalPath[MAX_PATH] = L"Trail of Bits\\fuzzkit\\arenas";

    if (PathCchCombine(FUZZ_ARENAS_PATH, MAX_PATH, roamingPath, arenasLocalPath) != S_OK) {
        LOG_F(ERROR, "initWorkingDirs: failed to combine arenas dir path (0x%x)", GetLastError());
    }

    CoTaskMemFree(roamingPath);
}

/* Generates a new run UUID, writes relevant run metadata files into the corresponding run metadata dir
    This, like many things in the server, is pretty overzealous about exiting after any errors, often without an
    explanation of what happened. TODO - fix this */
DWORD handleGenerateRunId(HANDLE hPipe) {
    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;
    UUID runId;
    wchar_t *runId_s;

    LOG_F(INFO, "handleGenerateRunId: received request");

    // NOTE(ww): On recent versions of Windows, UuidCreate generates a v4 UUID that
    // is sufficiently diffuse for our purposes (avoiding conflicts between runs).
    // See: https://stackoverflow.com/questions/35366368/does-uuidcreate-use-a-csprng
    UuidCreate(&runId);
    UuidToString(&runId, (RPC_WSTR *)&runId_s);

    wchar_t targetDir[MAX_PATH + 1] = {0};
    PathCchCombine(targetDir, MAX_PATH, FUZZ_WORKING_PATH, runId_s);
    if (!CreateDirectory(targetDir, NULL)) {
        LOG_F(ERROR, "handleGenerateRunId: couldn't create working directory (0x%x)", GetLastError());
        exit(1);
    }

    WriteFile(hPipe, &runId, sizeof(runId), &dwBytesWritten, NULL);
    LOG_F(INFO, "handleGenerateRunId: generated ID %S", runId_s);

    // get program name
    // TODO(ww): 8192 is the correct buffer size for the Windows command line, but
    // we should try to find a macro in the WINAPI for it here.
    wchar_t commandLine[8192] = {0};
    size_t size = 0;
    if (!ReadFile(hPipe, &size, sizeof(size), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleGenerateRunId: failed to read size of program name (0x%x)", GetLastError());
        LOG_F(ERROR, "size: %d", size);
        exit(1);
    }

    if (size > 8191) {
        LOG_F(ERROR, "handleGenerateRunId: program name length > 8191");
        exit(1);
    }

    if (!ReadFile(hPipe, commandLine, size, &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleGenerateRunId: failed to read size of argument list (0x%x)", GetLastError());
        exit(1);
    }

    wchar_t targetFile[MAX_PATH + 1] = { 0 };
    PathCchCombine(targetFile, MAX_PATH, targetDir, FUZZ_RUN_PROGRAM_TXT);
    HANDLE hFile = CreateFileW(targetFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "handleGenerateRunId: failed to open program.txt: %S (0x%x)", targetFile, GetLastError());
        exit(1);
    }

    if (!WriteFile(hFile, commandLine, size, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "handleGenerateRunId: failed to write program name to program.txt (0x%x)", GetLastError());
        exit(1);
    }

    if (!CloseHandle(hFile)) {
        LOG_F(ERROR, "handleGenerateRunId: failed to close program.txt (0x%x)", GetLastError());
        exit(1);
    }

    memset(commandLine, 0, 8192 * sizeof(wchar_t));

    // get program arguments
    size = 0;
    if (!ReadFile(hPipe, &size, sizeof(size), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleGenerateRunId: failed to read program argument list length (0x%x)", GetLastError());
        exit(1);
    }

    if (size > 8191) {
        LOG_F(ERROR, "handleGenerateRunId: program argument list length > 8191");
        exit(1);
    }

    if (!ReadFile(hPipe, commandLine, size, &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleGenerateRunId: failed to read program argument list (0x%x)", GetLastError());
        exit(1);
    }

    memset(targetFile, 0, (MAX_PATH + 1) * sizeof(wchar_t));
    PathCchCombine(targetFile, MAX_PATH, targetDir, FUZZ_RUN_ARGUMENTS_TXT);
    hFile = CreateFile(targetFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "handleGenerateRunId: failed to open arguments.txt: %S (0x%x)", targetFile, GetLastError());
        exit(1);
    }

    if (!WriteFile(hFile, commandLine, size, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "handleGenerateRunId: failed to write argument list to arguments.txt (0x%x)", GetLastError());
        exit(1);
    }

    if (!CloseHandle(hFile)) {
        LOG_F(ERROR, "handleGenerateRunId: failed to close arguments.txt (0x%x)", GetLastError());
        exit(1);
    }

    RpcStringFree((RPC_WSTR *)&runId_s);

    LOG_F(INFO, "handleGenerateRunId: finished");

    return 0;
}

/* Writes the fkt file in the event we found a crash. Stores information about the mutation that caused it */
DWORD writeFKT(HANDLE hFile, DWORD type, DWORD pathSize, wchar_t *filePath, size_t position, size_t size, uint8_t* buf)
{
    DWORD dwBytesWritten = 0;

    if (!WriteFile(hFile, "FKT\0", 4, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "writeFKT: failed to write FKT header (0x%x)", GetLastError());
        exit(1);
    }

    // only one type for right now, files
    if (!WriteFile(hFile, &type, sizeof(type), &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "writeFKT: failed to write type (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(hFile, &pathSize, sizeof(pathSize), &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "writeFKT: failed to write path size (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(hFile, filePath, pathSize * sizeof(wchar_t), &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "writeFKT: failed to write path (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(hFile, &position, sizeof(position), &dwBytesWritten, NULL)) {
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

DWORD handleRegisterMutation(HANDLE pipe)
{
    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;
    UUID run_id;
    wchar_t *run_id_s;

    LOG_F(INFO, "handleRegisterMutation: starting mutation registration");

    if (!ReadFile(pipe, &run_id, sizeof(run_id), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleRegisterMutation: failed to read run ID (0x%x)", GetLastError());
        exit(1);
    }

    UuidToString(&run_id, (RPC_WSTR *)&run_id_s);

    DWORD type = 0;
    if (!ReadFile(pipe, &type, sizeof(type), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleRegisterMutation: failed to read function type (0x%x)", GetLastError());
        exit(1);
    }

    DWORD mutate_count = 0;
    wchar_t mutate_fname[MAX_PATH + 1] = {0};
    if (!ReadFile(pipe, &mutate_count, sizeof(mutate_count), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleRegisterMutation: failed to read mutation count (0x%x)", GetLastError());
        exit(1);
    }
    StringCchPrintfW(mutate_fname, MAX_PATH, FUZZ_RUN_FKT_FMT, mutate_count);

    size_t resource_size = 0;
    if (!ReadFile(pipe, &resource_size, sizeof(resource_size), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleRegisterMutation: failed to read size of mutation filepath (0x%x)", GetLastError());
        exit(1);
    }

    if (resource_size > MAX_PATH) {
        LOG_F(ERROR, "handleRegisterMutation: resource_size > MAX_PATH", GetLastError());
        exit(1);
    }

    wchar_t resource_path[MAX_PATH + 1] = {0};

    // NOTE(ww): Interestingly, Windows distinguishes between a read of 0 bytes
    // and no read at all -- both the client and the server have to do either one or the
    // other, and failing to do either on one side causes a truncated read or write.
    if (resource_size > 0) {
        if (!ReadFile(pipe, &resource_path, resource_size * sizeof(wchar_t), &dwBytesRead, NULL)) {
            LOG_F(ERROR, "handleRegisterMutation: failed to read mutation filepath (0x%x)", GetLastError());
            exit(1);
        }

        resource_path[resource_size] = 0;

        LOG_F(INFO, "handleRegisterMutation: mutation file path: %S", resource_path);
    }
    else {
        LOG_F(WARNING, "handleRegisterMutation: the fuzzer didn't send us a file path!");
    }

    size_t position = 0;
    if (!ReadFile(pipe, &position, sizeof(position), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleRegisterMutation: failed to read mutation offset (0x%x)", GetLastError());
        exit(1);
    }

    size_t size = 0;
    if (!ReadFile(pipe, &size, sizeof(size), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleRegisterMutation: failed to read size of mutation buffer (0x%x)", GetLastError());
        exit(1);
    }

    uint8_t *buf = (uint8_t *) malloc(size);

    if (buf == NULL) {
        LOG_F(ERROR, "handleRegisterMutation: failed to allocate mutation buffer (0x%x)", GetLastError());
        exit(1);
    }

    if (!ReadFile(pipe, buf, (DWORD)size, &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleRegisterMutation: failed to read mutation buffer from pipe (0x%x)", GetLastError());
        exit(1);
    }

    if (dwBytesRead < size) {
        LOG_F(WARNING, "handleRegisterMutation: read fewer bytes than expected (%d < %lu)", dwBytesRead, size);
        size = dwBytesRead;
    }

    if (size < 0) {
        LOG_F(WARNING, "handleRegisterMutation: got an unexpectedly small buffer (%lu < 0), skipping mutation");
    }

    wchar_t targetDir[MAX_PATH + 1] = {0};
    wchar_t targetFile[MAX_PATH + 1] = {0};

    PathCchCombine(targetDir, MAX_PATH, FUZZ_WORKING_PATH, run_id_s);
    PathCchCombine(targetFile, MAX_PATH, targetDir, mutate_fname);

    HANDLE file = CreateFile(targetFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    if (file == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "handleRegisterMutation: failed to create FTK: %S (0x%x)", targetFile, GetLastError());
        exit(1);
    }

    writeFKT(file, type, resource_size, resource_path, position, size, buf);

    RpcStringFree((RPC_WSTR *)&run_id_s);

    return 0;
}

/* Gets the mutated bytes stored in the FKT file for mutation replay */
DWORD getBytesFKT(HANDLE hFile, uint8_t *buf, size_t size)
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
    wchar_t *runId_s;

    if (!ReadFile(hPipe, &runId, sizeof(UUID), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleReplay: failed to read run ID (0x%x)", GetLastError());
        exit(1);
    }

    UuidToString(&runId, (RPC_WSTR *)&runId_s);

    LOG_F(INFO, "Replaying for run id %S", runId_s);

    DWORD mutate_count = 0;
    wchar_t mutate_fname[MAX_PATH + 1] = {0};
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

    uint8_t *buf = (uint8_t *) malloc(size);

    if (buf == NULL) {
        LOG_F(ERROR, "handleReplay: failed to allocate replay buffer (0x%x)", GetLastError());
        exit(1);
    }

    wchar_t targetFile[MAX_PATH + 1];
    wchar_t targetDir[MAX_PATH + 1];
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

    RpcStringFree((RPC_WSTR *)&runId_s);

    return 0;
}

/* Deletes the run files to free up a Run ID if the last run didn't find a crash */
DWORD handleFinalizeRun(HANDLE hPipe)
{
    DWORD dwBytesRead = 0;
    UUID runId;
    wchar_t *runId_s;

    if (!ReadFile(hPipe, &runId, sizeof(UUID), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleFinalizeRun: failed to read run ID (0x%x)", GetLastError());
        exit(1);
    }

    UuidToString(&runId, (RPC_WSTR *)&runId_s);

    bool crash = false;
    if (!ReadFile(hPipe, &crash, sizeof(bool), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleFinalizeRun: failed to read crash status (0x%x)", GetLastError());
        exit(1);
    }

    bool preserve = false;
    if (!ReadFile(hPipe, &preserve, sizeof(bool), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleFinalizeRun: failed to read preserve flag (0x%x)", GetLastError());
        exit(1);
    }

    LOG_F(INFO, "handleFinalizeRun: finalizing %S", runId_s);

    if (!crash && !preserve) {
        LOG_F(INFO, "handleFinalizeRun: no crash, removing run %S", runId_s);
        EnterCriticalSection(&critId);

        wchar_t targetDir[MAX_PATH + 1] = {0};
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
    else if (!crash && preserve) {
        LOG_F(INFO, "handleFinalizeRun: no crash, but not removing files (requested)");
    }
    else {
        LOG_F(INFO, "handleFinalizeRun: crash found for run %S", runId_s);
    }

    RpcStringFree((RPC_WSTR *)&runId_s);

    return 0;
}

DWORD handleCrashPaths(HANDLE hPipe)
{
    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;
    UUID runId;
    wchar_t *runId_s;

    if (!ReadFile(hPipe, &runId, sizeof(UUID), &dwBytesRead, NULL)) {
        LOG_F(ERROR, "handleMiniDumpPath: failed to read UUID (0x%x)", GetLastError());
        exit(1);
    }

    UuidToString(&runId, (RPC_WSTR *)&runId_s);

    wchar_t targetDir[MAX_PATH + 1] = {0};
    wchar_t targetFile[MAX_PATH + 1] = {0};

    PathCchCombine(targetDir, MAX_PATH, FUZZ_WORKING_PATH, runId_s);
    PathCchCombine(targetFile, MAX_PATH, targetDir, FUZZ_RUN_CRASH_JSON);

    size_t size = lstrlen(targetFile) * sizeof(wchar_t);

    if (!WriteFile(hPipe, &size, sizeof(size), &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "handleCrashPaths: failed to write length of crash.json to pipe (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(hPipe, &targetFile, (DWORD)size, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "handleCrashPath: failed to write crash.json path to pipe (0x%x)", GetLastError());
        exit(1);
    }

    memset(targetFile, 0, (MAX_PATH + 1) * sizeof(wchar_t));
    PathCchCombine(targetFile, MAX_PATH, targetDir, FUZZ_RUN_MEM_DMP);

    size = lstrlen(targetFile) * sizeof(wchar_t);

    if (!WriteFile(hPipe, &size, sizeof(size), &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "handleCrashPath: failed to write length of mem.dmp path to pipe (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(hPipe, &targetFile, (DWORD)size, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "handleCrashPath: failed to write mem.dmp path to pipe (0x%x)", GetLastError());
        exit(1);
    }

    memset(targetFile, 0, (MAX_PATH + 1) * sizeof(wchar_t));
    PathCchCombine(targetFile, MAX_PATH, targetDir, FUZZ_RUN_INITIAL_DMP);

    size = lstrlen(targetFile) * sizeof(wchar_t);

    if (!WriteFile(hPipe, &size, sizeof(size), &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "handleCrashPath: failed to write length of initial.dmp path to pipe (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(hPipe, &targetFile, (DWORD)size, &dwBytesWritten, NULL)) {
        LOG_F(ERROR, "handleCrashPath: failed to write initial.dmp path to pipe (0x%x)", GetLastError());
        exit(1);
    }

    RpcStringFree((RPC_WSTR *)&runId_s);

    return 0;
}

/* Handles incoming connections from clients */
DWORD WINAPI threadHandler(void *lpvPipe)
{
    HANDLE hPipe = (HANDLE)lpvPipe;

    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;

    uint8_t event = EVT_INVALID;

    // NOTE(ww): This is a second event loop, inside of the infinite event loop that
    // creates each thread and calls threadHandler. We do this so that clients can
    // re-use their pipe instances to send multiple events -- with only the top-level
    // loop, each connection would be discarded after a single event.
    //
    // To end a "session", a client sends the EVT_SESSION_TEARDOWN event. "Session"
    // is in scare quotes because each session is essentially anonymous -- the server
    // only sees when they end, not which runs or events they correspond to.
    do {
        if (!ReadFile(hPipe, &event, sizeof(uint8_t), &dwBytesRead, NULL)) {
            if (GetLastError() != ERROR_BROKEN_PIPE){
                LOG_F(ERROR, "threadHandler: failed to read event (0x%x)", GetLastError());
                exit(1);
            }
            else{
                 // Pipe was broken when we tried to read it. Happens when the python client
                 // checks if it exists.
                return 0;
            }
        }

        LOG_F(INFO, "threadHandler: got event ID: %d", event);

        // Dispatch individual requests based on which event the client requested
        switch (event) {
            case EVT_RUN_ID:
                handleGenerateRunId(hPipe);
                break;
            case EVT_REGISTER_MUTATION:
                handleRegisterMutation(hPipe);
                break;
            case EVT_CRASH_PATHS:
                handleCrashPaths(hPipe);
                break;
            case EVT_REPLAY:
                handleReplay(hPipe);
                break;
            case EVT_RUN_COMPLETE:
                handleFinalizeRun(hPipe);
                break;
            case EVT_SESSION_TEARDOWN:
                LOG_F(INFO, "Ending a client's session with the server.");
                break;
            case EVT_GET_ARENA:
            case EVT_SET_ARENA:
                LOG_F(ERROR, "WIP events.");
                break;
            case EVT_MUTATION:
            case EVT_RUN_INFO:
            case EVT_CRASH_PATH:
            case EVT_MEM_DMP_PATH:
                LOG_F(WARNING, "threadHandler: deprecated event requested: EVT_MUTATION");
                event = EVT_INVALID;
                break;
            default:
                LOG_F(ERROR, "Unknown or invalid event %d", event);
                break;
        }
    } while (event != EVT_SESSION_TEARDOWN && event != EVT_INVALID);

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
    char logLocalPathA[MAX_PATH]= {0};
    size_t converted;
    wcstombs_s(&converted, logLocalPathA, MAX_PATH - 1, FUZZ_LOG, MAX_PATH - 1);
    loguru::add_file(logLocalPathA, loguru::Append, loguru::Verbosity_MAX);

    std::atexit(server_cleanup);

    initWorkingDirs();

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

        bool connected = ConnectNamedPipe(hPipe, NULL) ?
            TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (connected) {
            DWORD threadID;
            HANDLE hThread = CreateThread(
                NULL,
                0,
                threadHandler,
                (void*)hPipe,
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
