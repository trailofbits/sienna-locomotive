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

static CRITICAL_SECTION run_lock;
static HANDLE process_mutex = INVALID_HANDLE_VALUE;

static wchar_t FUZZ_WORKING_PATH[MAX_PATH] = L"";
static wchar_t FUZZ_ARENAS_PATH[MAX_PATH] = L"";
static wchar_t FUZZ_LOG[MAX_PATH] = L"";

/* concurrency protection */
static void lock_process()
{
    process_mutex = CreateMutex(NULL, false, L"fuzz_server_mutex");
    if (!process_mutex || process_mutex == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "lock_process: could not get process lock (handle)");
        exit(1);
    }

    DWORD result = WaitForSingleObject(process_mutex, 0);
    if (result != WAIT_OBJECT_0) {
        LOG_F(ERROR, "lock_process: could not get process lock (lock)");
        exit(1);
    }
}

// Called on process termination (by atexit).
static void server_cleanup()
{
    LOG_F(INFO, "server_cleanup: Called, cleaning things up");

    // NOTE(ww): We could probably check return codes here, but there's
    // no point -- the process is about to be destroyed anyways.
    ReleaseMutex(process_mutex);
    CloseHandle(process_mutex);
    DeleteCriticalSection(&run_lock);
}

// Initialize the global variable (FUZZ_LOG) containing the path to the logging file.
// NOTE(ww): We separate this from init_working_paths so that we can log any errors that
// happen to occur in init_working_paths.
static void init_logging_path()
{
    wchar_t *roaming_path;
    SHGetKnownFolderPath(FOLDERID_RoamingAppData, NULL, NULL, &roaming_path);

    if (PathCchCombine(FUZZ_LOG, MAX_PATH, roaming_path, L"Trail of Bits\\fuzzkit\\log\\server.log") != S_OK) {
        LOG_F(ERROR, "init_logging_path: failed to combine logfile path (0x%x)", GetLastError());
        exit(1);
    }

    CoTaskMemFree(roaming_path);
}

// Initialize the global variables containins the paths to the working directory,
// as well as the subdirectories and files we expect individual runs to produce.
// NOTE(ww): This should be kept up-to-date with fuzzer_config.py.
static void init_working_paths()
{
    wchar_t *roaming_path;
    SHGetKnownFolderPath(FOLDERID_RoamingAppData, NULL, NULL, &roaming_path);
    wchar_t runs_local_path[MAX_PATH] = L"Trail of Bits\\fuzzkit\\runs";

    if (PathCchCombine(FUZZ_WORKING_PATH, MAX_PATH, roaming_path, runs_local_path) != S_OK) {
        LOG_F(ERROR, "init_working_paths: failed to combine working dir path (0x%x)", GetLastError());
        exit(1);
    }

    wchar_t arenas_local_path[MAX_PATH] = L"Trail of Bits\\fuzzkit\\arenas";

    if (PathCchCombine(FUZZ_ARENAS_PATH, MAX_PATH, roaming_path, arenas_local_path) != S_OK) {
        LOG_F(ERROR, "init_working_paths: failed to combine arenas dir path (0x%x)", GetLastError());
    }

    CoTaskMemFree(roaming_path);
}

/* Writes the fkt file in the event we found a crash. Stores information about the mutation that caused it */
static void writeFKT(HANDLE fkt, DWORD type, size_t pathSize, wchar_t *filePath, size_t position, size_t size, uint8_t* buf)
{
    DWORD txsize;

    if (!WriteFile(fkt, "FKT\0", 4, &txsize, NULL)) {
        LOG_F(ERROR, "writeFKT: failed to write FKT header (0x%x)", GetLastError());
        exit(1);
    }

    // only one type for right now, files
    if (!WriteFile(fkt, &type, sizeof(type), &txsize, NULL)) {
        LOG_F(ERROR, "writeFKT: failed to write type (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(fkt, &pathSize, sizeof(pathSize), &txsize, NULL)) {
        LOG_F(ERROR, "writeFKT: failed to write path size (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(fkt, filePath, (DWORD) (pathSize * sizeof(wchar_t)), &txsize, NULL)) {
        LOG_F(ERROR, "writeFKT: failed to write path (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(fkt, &position, sizeof(position), &txsize, NULL)) {
        LOG_F(ERROR, "writeFKT: failed to write offset (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(fkt, &size, sizeof(size_t), &txsize, NULL)) {
        LOG_F(ERROR, "writeFKT: failed to write buffer size (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(fkt, buf, (DWORD)size, &txsize, NULL)) {
        LOG_F(ERROR, "writeFKT: failed to write buffer (0x%x)", GetLastError());
        exit(1);
    }

    if (!CloseHandle(fkt)) {
        LOG_F(ERROR, "writeFKT: failed to close FKT (0x%x)", GetLastError());
        exit(1);
    }
}

/* Gets the mutated bytes stored in the FKT file for mutation replay */
static void getBytesFKT(HANDLE fkt, uint8_t *buf, size_t size)
{
    DWORD txsize;
    size_t buf_size = 0;

    // TODO(ww): We shouldn't be hardcoding this offset.
    SetFilePointer(fkt, 0x18, NULL, FILE_BEGIN);
    if (!ReadFile(fkt, &buf_size, 4, &txsize, NULL)) {
        LOG_F(ERROR, "getBytesFKT: failed to read replay buffer size from FKT (0x%x)", GetLastError());
        exit(1);
    }

    if (buf_size < size) {
        size = buf_size;
    }

    LOG_F(INFO, "getBytesFKT: size=%lu", size);

    SetFilePointer(fkt, -(LONG)size, NULL, FILE_END);

    if (!ReadFile(fkt, buf, (DWORD) size, &txsize, NULL)) {
        LOG_F(ERROR, "getBytesFKT: failed to read replay buffer from FKT (0x%x)", GetLastError());
        exit(1);
    }

    LOG_F(INFO, "getBytesFKT: read in %02x %02x %02x %02x %02x %02x %02x %02x\n", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
}

static void dump_arena(wchar_t *arena_path, sl2_arena *arena)
{
    DWORD txsize;
    HANDLE file = CreateFile(
        arena_path,
        GENERIC_WRITE,
        0, NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (file == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "dump_arena: failed to open %S", arena_path);
        exit(1);
    }

    if (!WriteFile(file, arena->map, FUZZ_ARENA_SIZE, &txsize, NULL)) {
        LOG_F(ERROR, "dump_arena: failed to write arena to disk!");
        exit(1);
    }

    if (txsize != FUZZ_ARENA_SIZE) {
        LOG_F(ERROR, "dump_arena: %lu != %lu, truncated write?", txsize, FUZZ_ARENA_SIZE);
        exit(1);
    }

    CloseHandle(file);
}

static void load_arena(wchar_t *arena_path, sl2_arena *arena)
{
    DWORD txsize;
    HANDLE file = CreateFile(
        arena_path,
        GENERIC_READ,
        0, NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (file == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "load_arena: failed to open %S", arena_path);
        exit(1);
    }

    if (!ReadFile(file, arena->map, FUZZ_ARENA_SIZE, &txsize, NULL)) {
        LOG_F(ERROR, "load_arena: failed to read arena from disk!");
        exit(1);
    }

    if (txsize != FUZZ_ARENA_SIZE) {
        LOG_F(ERROR, "load_arena: %lu != %lu, truncated read?", txsize, FUZZ_ARENA_SIZE);
        exit(1);
    }

    CloseHandle(file);
}

/* Generates a new run UUID, writes relevant run metadata files into the corresponding run metadata dir
    This, like many things in the server, is pretty overzealous about exiting after any errors, often without an
    explanation of what happened. TODO - fix this */
static void handleGenerateRunId(HANDLE pipe)
{
    DWORD txsize;
    UUID run_id;
    wchar_t *run_id_s;

    LOG_F(INFO, "handleGenerateRunId: received request");

    // NOTE(ww): On recent versions of Windows, UuidCreate generates a v4 UUID that
    // is sufficiently diffuse for our purposes (avoiding conflicts between runs).
    // See: https://stackoverflow.com/questions/35366368/does-uuidcreate-use-a-csprng
    UuidCreate(&run_id);
    UuidToString(&run_id, (RPC_WSTR *)&run_id_s);

    wchar_t run_dir[MAX_PATH + 1] = {0};
    PathCchCombine(run_dir, MAX_PATH, FUZZ_WORKING_PATH, run_id_s);
    if (!CreateDirectory(run_dir, NULL)) {
        LOG_F(ERROR, "handleGenerateRunId: couldn't create working directory (0x%x)", GetLastError());
        exit(1);
    }

    WriteFile(pipe, &run_id, sizeof(run_id), &txsize, NULL);
    LOG_F(INFO, "handleGenerateRunId: generated ID %S", run_id_s);

    // get program name
    // TODO(ww): 8192 is the correct buffer size for the Windows command line, but
    // we should try to find a macro in the WINAPI for it here.
    wchar_t command_line[8192] = {0};
    size_t size = 0;
    if (!ReadFile(pipe, &size, sizeof(size), &txsize, NULL)) {
        LOG_F(ERROR, "handleGenerateRunId: failed to read size of program name (0x%x)", GetLastError());
        LOG_F(ERROR, "size: %d", size);
        exit(1);
    }

    if (size > 8191) {
        LOG_F(ERROR, "handleGenerateRunId: program name length %lu > 8191", size);
        exit(1);
    }

    if (!ReadFile(pipe, command_line, (DWORD) size, &txsize, NULL)) {
        LOG_F(ERROR, "handleGenerateRunId: failed to read size of argument list (0x%x)", GetLastError());
        exit(1);
    }

    wchar_t target_file[MAX_PATH + 1] = { 0 };
    PathCchCombine(target_file, MAX_PATH, run_dir, FUZZ_RUN_PROGRAM_TXT);
    HANDLE file = CreateFile(target_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    if (file == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "handleGenerateRunId: failed to open program.txt: %S (0x%x)", target_file, GetLastError());
        exit(1);
    }

    if (!WriteFile(file, command_line, (DWORD) size, &txsize, NULL)) {
        LOG_F(ERROR, "handleGenerateRunId: failed to write program name to program.txt (0x%x)", GetLastError());
        exit(1);
    }

    if (!CloseHandle(file)) {
        LOG_F(ERROR, "handleGenerateRunId: failed to close program.txt (0x%x)", GetLastError());
        exit(1);
    }

    memset(command_line, 0, 8192 * sizeof(wchar_t));

    // get program arguments
    size = 0;
    if (!ReadFile(pipe, &size, sizeof(size), &txsize, NULL)) {
        LOG_F(ERROR, "handleGenerateRunId: failed to read program argument list length (0x%x)", GetLastError());
        exit(1);
    }

    if (size > 8191) {
        LOG_F(ERROR, "handleGenerateRunId: program argument list length > 8191");
        exit(1);
    }

    if (!ReadFile(pipe, command_line, (DWORD) size, &txsize, NULL)) {
        LOG_F(ERROR, "handleGenerateRunId: failed to read program argument list (0x%x)", GetLastError());
        exit(1);
    }

    memset(target_file, 0, (MAX_PATH + 1) * sizeof(wchar_t));
    PathCchCombine(target_file, MAX_PATH, run_dir, FUZZ_RUN_ARGUMENTS_TXT);
    file = CreateFile(target_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    if (file == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "handleGenerateRunId: failed to open arguments.txt: %S (0x%x)", target_file, GetLastError());
        exit(1);
    }

    if (!WriteFile(file, command_line, (DWORD) size, &txsize, NULL)) {
        LOG_F(ERROR, "handleGenerateRunId: failed to write argument list to arguments.txt (0x%x)", GetLastError());
        exit(1);
    }

    if (!CloseHandle(file)) {
        LOG_F(ERROR, "handleGenerateRunId: failed to close arguments.txt (0x%x)", GetLastError());
        exit(1);
    }

    RpcStringFree((RPC_WSTR *)&run_id_s);

    LOG_F(INFO, "handleGenerateRunId: finished");
}

static void handleRegisterMutation(HANDLE pipe)
{
    DWORD txsize;
    UUID run_id;
    wchar_t *run_id_s;

    LOG_F(INFO, "handleRegisterMutation: starting mutation registration");

    if (!ReadFile(pipe, &run_id, sizeof(run_id), &txsize, NULL)) {
        LOG_F(ERROR, "handleRegisterMutation: failed to read run ID (0x%x)", GetLastError());
        exit(1);
    }

    UuidToString(&run_id, (RPC_WSTR *)&run_id_s);

    uint32_t type = 0;
    if (!ReadFile(pipe, &type, sizeof(type), &txsize, NULL)) {
        LOG_F(ERROR, "handleRegisterMutation: failed to read function type (0x%x)", GetLastError());
        exit(1);
    }

    uint32_t mutate_count = 0;
    wchar_t mutate_fname[MAX_PATH + 1] = {0};
    if (!ReadFile(pipe, &mutate_count, sizeof(mutate_count), &txsize, NULL)) {
        LOG_F(ERROR, "handleRegisterMutation: failed to read mutation count (0x%x)", GetLastError());
        exit(1);
    }
    StringCchPrintfW(mutate_fname, MAX_PATH, FUZZ_RUN_FKT_FMT, mutate_count);

    size_t resource_size = 0;
    if (!ReadFile(pipe, &resource_size, sizeof(resource_size), &txsize, NULL)) {
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
        if (!ReadFile(pipe, &resource_path, (DWORD) resource_size, &txsize, NULL)) {
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
    if (!ReadFile(pipe, &position, sizeof(position), &txsize, NULL)) {
        LOG_F(ERROR, "handleRegisterMutation: failed to read mutation offset (0x%x)", GetLastError());
        exit(1);
    }

    size_t size = 0;
    if (!ReadFile(pipe, &size, sizeof(size), &txsize, NULL)) {
        LOG_F(ERROR, "handleRegisterMutation: failed to read size of mutation buffer (0x%x)", GetLastError());
        exit(1);
    }

    uint8_t *buf = (uint8_t *) malloc(size);

    if (buf == NULL) {
        LOG_F(ERROR, "handleRegisterMutation: failed to allocate mutation buffer (size=%lu) (0x%x)", size, GetLastError());
        exit(1);
    }

    if (!ReadFile(pipe, buf, (DWORD)size, &txsize, NULL)) {
        LOG_F(ERROR, "handleRegisterMutation: failed to read mutation buffer from pipe (0x%x)", GetLastError());
        exit(1);
    }

    if (txsize < size) {
        LOG_F(WARNING, "handleRegisterMutation: read fewer bytes than expected (%d < %lu)", txsize, size);
        size = txsize;
    }

    if (size < 0) {
        LOG_F(WARNING, "handleRegisterMutation: got an unexpectedly small buffer (%lu < 0), skipping mutation");
    }

    wchar_t run_dir[MAX_PATH + 1] = {0};
    wchar_t target_file[MAX_PATH + 1] = {0};

    PathCchCombine(run_dir, MAX_PATH, FUZZ_WORKING_PATH, run_id_s);
    PathCchCombine(target_file, MAX_PATH, run_dir, mutate_fname);

    // TODO(ww): WriteFKT should take a filename, rather than an open file handle.
    HANDLE file = CreateFile(target_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    if (file == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "handleRegisterMutation: failed to create FTK: %S (0x%x)", target_file, GetLastError());
        exit(1);
    }

    writeFKT(file, type, resource_size, resource_path, position, size, buf);

    RpcStringFree((RPC_WSTR *)&run_id_s);
}

/* Handles requests over the named pipe from the triage client for replays of mutated bytes */
static void handleReplay(HANDLE pipe)
{
    DWORD txsize;
    UUID run_id;
    wchar_t *run_id_s;

    if (!ReadFile(pipe, &run_id, sizeof(run_id), &txsize, NULL)) {
        LOG_F(ERROR, "handleReplay: failed to read run ID (0x%x)", GetLastError());
        exit(1);
    }

    UuidToString(&run_id, (RPC_WSTR *)&run_id_s);

    LOG_F(INFO, "Replaying for run id %S", run_id_s);

    uint32_t mutate_count = 0;
    wchar_t mutate_fname[MAX_PATH + 1] = {0};
    if (!ReadFile(pipe, &mutate_count, sizeof(mutate_count), &txsize, NULL)) {
        LOG_F(ERROR, "handleReplay: failed to read mutate count (0x%x)", GetLastError());
        exit(1);
    }

    StringCchPrintfW(mutate_fname, MAX_PATH, FUZZ_RUN_FKT_FMT, mutate_count);

    size_t size = 0;
    if (!ReadFile(pipe, &size, sizeof(size), &txsize, NULL)) {
        LOG_F(ERROR, "handleReplay: failed to read size of replay buffer (0x%x)", GetLastError());
        exit(1);
    }

    uint8_t *buf = (uint8_t *) malloc(size);

    if (buf == NULL) {
        LOG_F(ERROR, "handleReplay: failed to allocate replay buffer (0x%x)", GetLastError());
        exit(1);
    }

    wchar_t target_file[MAX_PATH + 1];
    wchar_t run_dir[MAX_PATH + 1];
    PathCchCombine(run_dir, MAX_PATH, FUZZ_WORKING_PATH, run_id_s);
    PathCchCombine(target_file, MAX_PATH, run_dir, mutate_fname);

    DWORD attrs = GetFileAttributes(target_file);

    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        LOG_F(ERROR, "handleReplay: missing FKT or is a directory: %S", target_file);
        exit(1);
    }

    // TODO(ww): getBytesFKT should take a filename, rather an an open handle.
    HANDLE hFile = CreateFile(target_file, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "handleReplay: failed to open FKT: %S (0x%x)", target_file, GetLastError());
        exit(1);
    }

    getBytesFKT(hFile, buf, size);

    if (!WriteFile(pipe, buf, (DWORD) size, &txsize, NULL)) {
        LOG_F(ERROR, "handleReplay: failed to write replay buffer (0x%x)", GetLastError());
        exit(1);
    }

    if (!CloseHandle(hFile)) {
        LOG_F(ERROR, "handleReplay: failed to close FKT (0x%x)", GetLastError());
        exit(1);
    }

    RpcStringFree((RPC_WSTR *)&run_id_s);
}

/* Deletes the run files to free up a Run ID if the last run didn't find a crash */
static void handleFinalizeRun(HANDLE pipe)
{
    DWORD txsize;
    UUID run_id;
    wchar_t *run_id_s;

    if (!ReadFile(pipe, &run_id, sizeof(UUID), &txsize, NULL)) {
        LOG_F(ERROR, "handleFinalizeRun: failed to read run ID (0x%x)", GetLastError());
        exit(1);
    }

    UuidToString(&run_id, (RPC_WSTR *)&run_id_s);

    bool crash = false;
    if (!ReadFile(pipe, &crash, sizeof(bool), &txsize, NULL)) {
        LOG_F(ERROR, "handleFinalizeRun: failed to read crash status (0x%x)", GetLastError());
        exit(1);
    }

    bool preserve = false;
    if (!ReadFile(pipe, &preserve, sizeof(bool), &txsize, NULL)) {
        LOG_F(ERROR, "handleFinalizeRun: failed to read preserve flag (0x%x)", GetLastError());
        exit(1);
    }

    LOG_F(INFO, "handleFinalizeRun: finalizing %S", run_id_s);

    if (!crash && !preserve) {
        LOG_F(INFO, "handleFinalizeRun: no crash, removing run %S", run_id_s);
        EnterCriticalSection(&run_lock);

        wchar_t run_dir[MAX_PATH + 1] = {0};
        PathCchCombine(run_dir, MAX_PATH, FUZZ_WORKING_PATH, run_id_s);

        SHFILEOPSTRUCT remove_op = {
            NULL,
            FO_DELETE,
            run_dir,
            L"",
            FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT,
            false,
            NULL,
            L""
        };

        SHFileOperation(&remove_op);
        LeaveCriticalSection(&run_lock);
    }
    else if (!crash && preserve) {
        LOG_F(INFO, "handleFinalizeRun: no crash, but not removing files (requested)");
    }
    else {
        LOG_F(INFO, "handleFinalizeRun: crash found for run %S", run_id_s);
    }

    RpcStringFree((RPC_WSTR *)&run_id_s);
}

static void handleGetArena(HANDLE pipe)
{
    DWORD txsize;
    size_t size = 0;
    sl2_arena arena = {0};

    if (!ReadFile(pipe, &size, sizeof(size), &txsize, NULL)) {
        LOG_F(ERROR, "handleGetArena: failed to read arena ID size (0x%x)", GetLastError());
        exit(1);
    }

    if (size != SL2_HASH_LEN * sizeof(wchar_t)) {
        LOG_F(ERROR, "handleGetArena: wrong arena ID size %lu != %lu", size, SL2_HASH_LEN * sizeof(wchar_t));
        exit(1);
    }

    if (!ReadFile(pipe, arena.id, (DWORD) size, &txsize, NULL)) {
        LOG_F(ERROR, "handleGetArena: failed to read arena ID (0x%x)", GetLastError());
        exit(1);
    }

    LOG_F(INFO, "handleGetArena: got arena ID: %S", arena.id);

    wchar_t arena_path[MAX_PATH + 1] = {0};

    PathCchCombine(arena_path, MAX_PATH, FUZZ_ARENAS_PATH, arena.id);

    DWORD attrs = GetFileAttributes(arena_path);

    if (attrs == INVALID_FILE_ATTRIBUTES) {
        LOG_F(INFO, "handleGetArena: no arena found, creating one");
        dump_arena(arena_path, &arena);
    }
    else {
        LOG_F(INFO, "handleGetArena: arena found, loading from disk");
        load_arena(arena_path, &arena);
    }

    if (!WriteFile(pipe, arena.map, FUZZ_ARENA_SIZE, &txsize, NULL)) {
        LOG_F(ERROR, "handleGetArena: failed to write arena (0x%x)", GetLastError());
    }
}

static void handleSetArena(HANDLE pipe)
{
    DWORD txsize;
    size_t size = 0;
    sl2_arena arena = {0};

    if (!ReadFile(pipe, &size, sizeof(size), &txsize, NULL)) {
        LOG_F(ERROR, "handleSetArena: failed to read arena ID size (0x%x)", GetLastError());
        exit(1);
    }

    if (size != SL2_HASH_LEN * sizeof(wchar_t)) {
        LOG_F(ERROR, "handleSetArena: wrong arena ID size %lu != %lu", size, SL2_HASH_LEN * sizeof(wchar_t));
        exit(1);
    }

    if (!ReadFile(pipe, arena.id, (DWORD) size, &txsize, NULL)) {
        LOG_F(ERROR, "handleSetArena: failed to read arena ID (0x%x)", GetLastError());
        exit(1);
    }

    LOG_F(INFO, "handleSetArena: got arena ID: %S", arena.id);

    wchar_t arena_path[MAX_PATH + 1] = {0};

    PathCchCombine(arena_path, MAX_PATH, FUZZ_ARENAS_PATH, arena.id);

    if (!ReadFile(pipe, arena.map, FUZZ_ARENA_SIZE, &txsize, NULL)) {
        LOG_F(ERROR, "handleSetArena: failed to read arena (0x%x)", GetLastError());
    }

    dump_arena(arena_path, &arena);
}

static void handleCrashPaths(HANDLE pipe)
{
    DWORD txsize;
    UUID run_id;
    wchar_t *run_id_s;

    if (!ReadFile(pipe, &run_id, sizeof(UUID), &txsize, NULL)) {
        LOG_F(ERROR, "handleMiniDumpPath: failed to read UUID (0x%x)", GetLastError());
        exit(1);
    }

    UuidToString(&run_id, (RPC_WSTR *)&run_id_s);

    wchar_t run_dir[MAX_PATH + 1] = {0};
    wchar_t target_file[MAX_PATH + 1] = {0};

    PathCchCombine(run_dir, MAX_PATH, FUZZ_WORKING_PATH, run_id_s);
    PathCchCombine(target_file, MAX_PATH, run_dir, FUZZ_RUN_CRASH_JSON);

    size_t size = lstrlen(target_file) * sizeof(wchar_t);

    if (!WriteFile(pipe, &size, sizeof(size), &txsize, NULL)) {
        LOG_F(ERROR, "handleCrashPaths: failed to write length of crash.json to pipe (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(pipe, &target_file, (DWORD)size, &txsize, NULL)) {
        LOG_F(ERROR, "handleCrashPath: failed to write crash.json path to pipe (0x%x)", GetLastError());
        exit(1);
    }

    memset(target_file, 0, (MAX_PATH + 1) * sizeof(wchar_t));
    PathCchCombine(target_file, MAX_PATH, run_dir, FUZZ_RUN_MEM_DMP);

    size = lstrlen(target_file) * sizeof(wchar_t);

    if (!WriteFile(pipe, &size, sizeof(size), &txsize, NULL)) {
        LOG_F(ERROR, "handleCrashPath: failed to write length of mem.dmp path to pipe (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(pipe, &target_file, (DWORD)size, &txsize, NULL)) {
        LOG_F(ERROR, "handleCrashPath: failed to write mem.dmp path to pipe (0x%x)", GetLastError());
        exit(1);
    }

    memset(target_file, 0, (MAX_PATH + 1) * sizeof(wchar_t));
    PathCchCombine(target_file, MAX_PATH, run_dir, FUZZ_RUN_INITIAL_DMP);

    size = lstrlen(target_file) * sizeof(wchar_t);

    if (!WriteFile(pipe, &size, sizeof(size), &txsize, NULL)) {
        LOG_F(ERROR, "handleCrashPath: failed to write length of initial.dmp path to pipe (0x%x)", GetLastError());
        exit(1);
    }

    if (!WriteFile(pipe, &target_file, (DWORD)size, &txsize, NULL)) {
        LOG_F(ERROR, "handleCrashPath: failed to write initial.dmp path to pipe (0x%x)", GetLastError());
        exit(1);
    }

    RpcStringFree((RPC_WSTR *)&run_id_s);
}

static void handlePing(HANDLE pipe)
{
    DWORD txsize;
    uint8_t ok = 1;

    LOG_F(INFO, "handlePing: ponging the client");

    if (!WriteFile(pipe, &ok, sizeof(ok), &txsize, NULL)) {
        LOG_F(ERROR, "handleCrashPath: failed to write pong status to pipe (0x%x)", GetLastError());
        exit(1);
    }
}

static void destroy_pipe(HANDLE pipe)
{
    if (!FlushFileBuffers(pipe)) {
        LOG_F(ERROR, "threadHandler: failed to flush pipe (0x%x)", GetLastError());
        exit(1);
    }

    if (!DisconnectNamedPipe(pipe)) {
        LOG_F(ERROR, "threadHandler: failed to disconnect pipe (0x%x)", GetLastError());
        exit(1);
    }

    if (!CloseHandle(pipe)) {
        LOG_F(ERROR, "threadHandler: failed to close pipe (0x%x)", GetLastError());
        exit(1);
    }
}

/* Handles incoming connections from clients */
static DWORD WINAPI threadHandler(void *lpvPipe)
{
    HANDLE pipe = (HANDLE)lpvPipe;
    DWORD txsize;
    uint8_t event;

    // NOTE(ww): This is a second event loop, inside of the infinite event loop that
    // creates each thread and calls threadHandler. We do this so that clients can
    // re-use their pipe instances to send multiple events -- with only the top-level
    // loop, each connection would be discarded after a single event.
    //
    // To end a "session", a client sends the EVT_SESSION_TEARDOWN event. "Session"
    // is in scare quotes because each session is essentially anonymous -- the server
    // only sees when they end, not which runs or events they correspond to.
    do {
        event = EVT_INVALID;

        LOG_F(INFO, "threadHandler: waiting for the next event!");

        if (!ReadFile(pipe, &event, sizeof(event), &txsize, NULL)) {
            if (GetLastError() != ERROR_BROKEN_PIPE) {
                LOG_F(ERROR, "threadHandler: failed to read event (0x%x)", GetLastError());
                exit(1);
            }
            else {
                // Pipe was broken when we tried to read it. Happens when the python client
                // checks if it exists.
                LOG_F(ERROR, "threadHandler: broken pipe! ending session on event=%d", event);
                destroy_pipe(pipe);
                return 0;
            }
        }

        LOG_F(INFO, "threadHandler: got event ID: %d", event);

        // Dispatch individual requests based on which event the client requested
        switch (event) {
            case EVT_RUN_ID:
                handleGenerateRunId(pipe);
                break;
            case EVT_REGISTER_MUTATION:
                handleRegisterMutation(pipe);
                break;
            case EVT_CRASH_PATHS:
                handleCrashPaths(pipe);
                break;
            case EVT_REPLAY:
                handleReplay(pipe);
                break;
            case EVT_RUN_COMPLETE:
                handleFinalizeRun(pipe);
                break;
            case EVT_GET_ARENA:
                handleGetArena(pipe);
                break;
            case EVT_SET_ARENA:
                handleSetArena(pipe);
                break;
            case EVT_PING:
                handlePing(pipe);
                break;
            case EVT_SESSION_TEARDOWN:
                LOG_F(INFO, "threadHandler: ending a client's session with the server.");
                break;
            case EVT_MUTATION:
            case EVT_RUN_INFO:
            case EVT_CRASH_PATH:
            case EVT_MEM_DMP_PATH:
                LOG_F(WARNING, "threadHandler: deprecated event requested.");
                event = EVT_INVALID;
                break;
            default:
                LOG_F(ERROR, "threadHandler: unknown or invalid event %d", event);
                break;
        }
    } while (event != EVT_SESSION_TEARDOWN && event != EVT_INVALID);

    LOG_F(INFO, "threadHandler: closing pipe after event=%d", event);
    destroy_pipe(pipe);

    return 0;
}

// Init dirs and create a new thread to handle input from the named pipe
int main(int mArgc, char **mArgv)
{
    init_logging_path();
    loguru::init(mArgc, mArgv);
    char log_path_mbs[MAX_PATH + 1]= {0};
    wcstombs_s(NULL, log_path_mbs, MAX_PATH, FUZZ_LOG, MAX_PATH);
    loguru::add_file(log_path_mbs, loguru::Append, loguru::Verbosity_MAX);

    std::atexit(server_cleanup);

    init_working_paths();

    LOG_F(INFO, "main: server started!");

    lock_process();

    InitializeCriticalSection(&run_lock);

    while (1) {
        HANDLE pipe = CreateNamedPipe(
            FUZZ_SERVER_PATH,
            PIPE_ACCESS_DUPLEX,
            PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            BUFSIZ,
            BUFSIZ,
            0,
            NULL
        );

        if (pipe == INVALID_HANDLE_VALUE) {
            LOG_F(ERROR, "main: could not create pipe");
            return 1;
        }

        bool connected = ConnectNamedPipe(pipe, NULL) ?
            true : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (connected) {
            HANDLE thread = CreateThread(
                NULL,
                0,
                threadHandler,
                (void *) pipe,
                0,
                NULL);

            if (thread == NULL)
            {
                LOG_F(ERROR, "main: CreateThread failed (0x%x)\n", GetLastError());
                return -1;
            }
            else {
                CloseHandle(thread);
            }
        }
        else {
            LOG_F(ERROR, "main: could not connect to pipe");
            CloseHandle(pipe);
        }
    }

    return 0;
}
