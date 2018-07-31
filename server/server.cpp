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
// NOTE(ww): Windows likes to be special. We macro strdup to _strdup
// here because strdup is technically nonstandard.
#define strdup _strdup
#include "vendor/loguru.hpp"
#undef strdup

#include "server.hpp"

// Convenience macros for logging.
#define SL2_SERVER_LOG(level, fmt, ...) LOG_F(level, __FUNCTION__ ": " fmt, __VA_ARGS__)
// NOTE(ww): The MS preprocessor is smart enough to remove the trailing comma in most
// sitations, but not when __VA_ARGS__ is *not* the last argument. So we put
// the GLE status at the beginning instead.
#define SL2_SERVER_LOG_GLE(level, fmt, ...) SL2_SERVER_LOG(level, "(GLE=%lu) " fmt, GetLastError(), __VA_ARGS__)
#define SL2_SERVER_LOG_INFO(fmt, ...) SL2_SERVER_LOG(INFO, fmt, __VA_ARGS__)
#define SL2_SERVER_LOG_WARN(fmt, ...) SL2_SERVER_LOG_GLE(WARNING, fmt, __VA_ARGS__)
#define SL2_SERVER_LOG_ERROR(fmt, ...) SL2_SERVER_LOG_GLE(ERROR, fmt, __VA_ARGS__)
#define SL2_SERVER_LOG_FATAL(fmt, ...) SL2_SERVER_LOG_GLE(FATAL, fmt, __VA_ARGS__)

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
        SL2_SERVER_LOG_FATAL("could not get create process lock");
    }

    DWORD result = WaitForSingleObject(process_mutex, 0);
    if (result != WAIT_OBJECT_0) {
        SL2_SERVER_LOG_FATAL("could not obtain process lock");
    }
}

// Called on process termination (by atexit).
static void server_cleanup()
{
    SL2_SERVER_LOG_INFO("Called, cleaning things up");

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
        SL2_SERVER_LOG_FATAL("failed to combine logfile path");
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
        SL2_SERVER_LOG_FATAL("failed to combine working dir path");
    }

    wchar_t arenas_local_path[MAX_PATH] = L"Trail of Bits\\fuzzkit\\arenas";

    if (PathCchCombine(FUZZ_ARENAS_PATH, MAX_PATH, roaming_path, arenas_local_path) != S_OK) {
        SL2_SERVER_LOG_FATAL("failed to combine arenas dir path");
    }

    CoTaskMemFree(roaming_path);
}

/* Writes the fkt file in the event we found a crash. Stores information about the mutation that caused it */
static void write_fkt(wchar_t *target_file, uint32_t type, size_t resource_size, wchar_t *resource_path, size_t position, size_t size, uint8_t* buf)
{
    DWORD txsize;
    HANDLE fkt = CreateFile(target_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    if (fkt == INVALID_HANDLE_VALUE) {
        SL2_SERVER_LOG_FATAL("write_fkt: failed to create FTK: %S", target_file);
    }

    if (!WriteFile(fkt, "FKT\0", 4, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("write_fkt: failed to write FKT header");
    }

    // only one type for right now, files
    if (!WriteFile(fkt, &type, sizeof(type), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("write_fkt: failed to write type");
    }

    if (!WriteFile(fkt, &resource_size, sizeof(resource_size), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("write_fkt: failed to write path size");
    }

    if (!WriteFile(fkt, resource_path, (DWORD) (resource_size * sizeof(wchar_t)), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("write_fkt: failed to write path");
    }

    if (!WriteFile(fkt, &position, sizeof(position), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("write_fkt: failed to write offset");
    }

    if (!WriteFile(fkt, &size, sizeof(size_t), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("write_fkt: failed to write buffer size");
    }

    if (!WriteFile(fkt, buf, (DWORD)size, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("write_fkt: failed to write buffer");
    }

    if (!CloseHandle(fkt)) {
        SL2_SERVER_LOG_FATAL("write_fkt: failed to close FKT");
    }
}

/* Gets the mutated bytes stored in the FKT file for mutation replay */
static void get_bytes_fkt(wchar_t *target_file, uint8_t *buf, size_t size)
{
    DWORD txsize;
    size_t buf_size = 0;
    HANDLE fkt = CreateFile(target_file, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (fkt == INVALID_HANDLE_VALUE) {
        SL2_SERVER_LOG_FATAL("failed to open FKT: %S", target_file);
    }

    // TODO(ww): We shouldn't be hardcoding this offset.
    SetFilePointer(fkt, 0x18, NULL, FILE_BEGIN);
    if (!ReadFile(fkt, &buf_size, 4, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read replay buffer size from FKT");
    }

    if (buf_size < size) {
        size = buf_size;
    }

    SL2_SERVER_LOG_INFO("buffer size=%lu", size);

    SetFilePointer(fkt, -(LONG)size, NULL, FILE_END);

    if (!ReadFile(fkt, buf, (DWORD) size, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read replay buffer from FKT");
    }

    if (!CloseHandle(fkt)) {
        SL2_SERVER_LOG_FATAL("failed to close FKT");
    }

    SL2_SERVER_LOG_INFO("read in %02x %02x %02x %02x %02x %02x %02x %02x\n", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
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
        SL2_SERVER_LOG_FATAL("dump_arena: failed to open %S", arena_path);
    }

    if (!WriteFile(file, arena->map, FUZZ_ARENA_SIZE, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("dump_arena: failed to write arena to disk!");
    }

    if (txsize != FUZZ_ARENA_SIZE) {
        SL2_SERVER_LOG_FATAL("dump_arena: %lu != %lu, truncated write?", txsize, FUZZ_ARENA_SIZE);
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
        SL2_SERVER_LOG_FATAL("failed to open %S", arena_path);
    }

    if (!ReadFile(file, arena->map, FUZZ_ARENA_SIZE, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read arena from disk!");
    }

    if (txsize != FUZZ_ARENA_SIZE) {
        SL2_SERVER_LOG_FATAL("%lu != %lu, truncated read?", txsize, FUZZ_ARENA_SIZE);
    }

    CloseHandle(file);
}

/* Generates a new run UUID, writes relevant run metadata files into the corresponding run metadata dir
    This, like many things in the server, is pretty overzealous about exiting after any errors, often without an
    explanation of what happened. TODO - fix this */
static void handle_generate_run_id(HANDLE pipe)
{
    DWORD txsize;
    UUID run_id;
    wchar_t *run_id_s;

    SL2_SERVER_LOG_INFO("received request");

    // NOTE(ww): On recent versions of Windows, UuidCreate generates a v4 UUID that
    // is sufficiently diffuse for our purposes (avoiding conflicts between runs).
    // See: https://stackoverflow.com/questions/35366368/does-uuidcreate-use-a-csprng
    UuidCreate(&run_id);
    UuidToString(&run_id, (RPC_WSTR *)&run_id_s);

    wchar_t run_dir[MAX_PATH + 1] = {0};
    PathCchCombine(run_dir, MAX_PATH, FUZZ_WORKING_PATH, run_id_s);
    if (!CreateDirectory(run_dir, NULL)) {
        SL2_SERVER_LOG_FATAL("couldn't create working directory");
    }

    WriteFile(pipe, &run_id, sizeof(run_id), &txsize, NULL);
    SL2_SERVER_LOG_INFO("generated ID %S", run_id_s);

    // get program name
    wchar_t command_line[SL2_ARGV_LEN] = {0};
    size_t size = 0;
    if (!ReadFile(pipe, &size, sizeof(size), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read size of program name (size=%lu)", size);
    }

    if ((size / sizeof(wchar_t)) > SL2_ARGV_LEN - 1) {
        SL2_SERVER_LOG_FATAL("program name length %lu > SL2_ARGV_LEN - 1", size);
    }

    if (!ReadFile(pipe, command_line, (DWORD) size, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read size of argument list");
    }

    wchar_t target_file[MAX_PATH + 1] = {0};
    PathCchCombine(target_file, MAX_PATH, run_dir, FUZZ_RUN_PROGRAM_TXT);
    HANDLE file = CreateFile(target_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    if (file == INVALID_HANDLE_VALUE) {
        SL2_SERVER_LOG_FATAL("failed to open program.txt: %S", target_file);
    }

    if (!WriteFile(file, command_line, (DWORD) size, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write program name to program.txt");
    }

    if (!CloseHandle(file)) {
        SL2_SERVER_LOG_FATAL("failed to close program.txt");
    }

    memset(command_line, 0, SL2_ARGV_LEN * sizeof(wchar_t));

    // get program arguments
    size = 0;
    if (!ReadFile(pipe, &size, sizeof(size), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read program argument list length");
    }

    if ((size / sizeof(wchar_t)) > SL2_ARGV_LEN - 1) {
        SL2_SERVER_LOG_FATAL("program argument list length > SL2_ARGV_LEN - 1");
    }

    if (!ReadFile(pipe, command_line, (DWORD) size, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read program argument list");
    }

    memset(target_file, 0, (MAX_PATH + 1) * sizeof(wchar_t));
    PathCchCombine(target_file, MAX_PATH, run_dir, FUZZ_RUN_ARGUMENTS_TXT);
    file = CreateFile(target_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    if (file == INVALID_HANDLE_VALUE) {
        SL2_SERVER_LOG_FATAL("failed to open arguments.txt: %S", target_file);
    }

    if (!WriteFile(file, command_line, (DWORD) size, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write argument list to arguments.txt");
    }

    if (!CloseHandle(file)) {
        SL2_SERVER_LOG_FATAL("failed to close arguments.txt");
    }

    RpcStringFree((RPC_WSTR *)&run_id_s);

    SL2_SERVER_LOG_INFO("finished");
}

static void handle_register_mutation(HANDLE pipe)
{
    DWORD txsize;
    UUID run_id;
    wchar_t *run_id_s;

    SL2_SERVER_LOG_INFO("starting mutation registration");

    if (!ReadFile(pipe, &run_id, sizeof(run_id), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read run ID");
    }

    UuidToString(&run_id, (RPC_WSTR *)&run_id_s);

    uint32_t type = 0;
    if (!ReadFile(pipe, &type, sizeof(type), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read function type");
    }

    uint32_t mutate_count = 0;
    wchar_t mutate_fname[MAX_PATH + 1] = {0};
    if (!ReadFile(pipe, &mutate_count, sizeof(mutate_count), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read mutation count");
    }
    StringCchPrintfW(mutate_fname, MAX_PATH, FUZZ_RUN_FKT_FMT, mutate_count);

    size_t resource_size = 0;
    if (!ReadFile(pipe, &resource_size, sizeof(resource_size), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read size of mutation filepath");
    }

    if (resource_size > MAX_PATH) {
        SL2_SERVER_LOG_FATAL("resource_size > MAX_PATH");
    }

    wchar_t resource_path[MAX_PATH + 1] = {0};

    // NOTE(ww): Interestingly, Windows distinguishes between a read of 0 bytes
    // and no read at all -- both the client and the server have to do either one or the
    // other, and failing to do either on one side causes a truncated read or write.
    if (resource_size > 0) {
        if (!ReadFile(pipe, &resource_path, (DWORD) resource_size, &txsize, NULL)) {
            SL2_SERVER_LOG_FATAL("failed to read mutation filepath");
        }

        resource_path[resource_size] = 0;

        SL2_SERVER_LOG_INFO("mutation file path: %S", resource_path);
    }
    else {
        SL2_SERVER_LOG_WARN("the fuzzer didn't send us a file path!");
    }

    size_t position = 0;
    if (!ReadFile(pipe, &position, sizeof(position), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read mutation offset");
    }

    size_t size = 0;
    if (!ReadFile(pipe, &size, sizeof(size), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read size of mutation buffer");
    }

    uint8_t *buf = (uint8_t *) malloc(size);

    if (buf == NULL) {
        SL2_SERVER_LOG_FATAL("failed to allocate mutation buffer (size=%lu)", size);
    }

    if (!ReadFile(pipe, buf, (DWORD)size, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read mutation buffer from pipe");
    }

    if (txsize < size) {
        SL2_SERVER_LOG_WARN("read fewer bytes than expected (%d < %lu)", txsize, size);
        size = txsize;
    }

    // TODO(ww): Do we need this?
    if (size < 0) {
        SL2_SERVER_LOG_WARN("got an unexpectedly small buffer (%lu < 0), skipping mutation");
    }

    wchar_t run_dir[MAX_PATH + 1] = {0};
    wchar_t target_file[MAX_PATH + 1] = {0};

    PathCchCombine(run_dir, MAX_PATH, FUZZ_WORKING_PATH, run_id_s);
    PathCchCombine(target_file, MAX_PATH, run_dir, mutate_fname);

    write_fkt(target_file, type, resource_size, resource_path, position, size, buf);

    RpcStringFree((RPC_WSTR *)&run_id_s);
}

/* Handles requests over the named pipe from the triage client for replays of mutated bytes */
static void handle_replay(HANDLE pipe)
{
    DWORD txsize;
    UUID run_id;
    wchar_t *run_id_s;

    if (!ReadFile(pipe, &run_id, sizeof(run_id), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read run ID");
    }

    UuidToString(&run_id, (RPC_WSTR *)&run_id_s);

    SL2_SERVER_LOG_INFO("Replaying for run id %S", run_id_s);

    uint32_t mutate_count = 0;
    wchar_t mutate_fname[MAX_PATH + 1] = {0};
    if (!ReadFile(pipe, &mutate_count, sizeof(mutate_count), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read mutate count");
    }

    StringCchPrintfW(mutate_fname, MAX_PATH, FUZZ_RUN_FKT_FMT, mutate_count);

    size_t size = 0;
    if (!ReadFile(pipe, &size, sizeof(size), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read size of replay buffer");
    }

    uint8_t *buf = (uint8_t *) malloc(size);

    if (buf == NULL) {
        SL2_SERVER_LOG_FATAL("failed to allocate replay buffer");
    }

    wchar_t target_file[MAX_PATH + 1];
    wchar_t run_dir[MAX_PATH + 1];
    PathCchCombine(run_dir, MAX_PATH, FUZZ_WORKING_PATH, run_id_s);
    PathCchCombine(target_file, MAX_PATH, run_dir, mutate_fname);

    DWORD attrs = GetFileAttributes(target_file);

    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        SL2_SERVER_LOG_FATAL("handle_replay: missing FKT or is a directory: %S", target_file);
    }

    get_bytes_fkt(target_file, buf, size);

    if (!WriteFile(pipe, buf, (DWORD) size, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write replay buffer");
    }

    RpcStringFree((RPC_WSTR *)&run_id_s);
}

/* Deletes the run files to free up a Run ID if the last run didn't find a crash */
static void handle_finalize_run(HANDLE pipe)
{
    DWORD txsize;
    UUID run_id;
    wchar_t *run_id_s;

    if (!ReadFile(pipe, &run_id, sizeof(UUID), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read run ID");
    }

    UuidToString(&run_id, (RPC_WSTR *)&run_id_s);

    bool crash = false;
    if (!ReadFile(pipe, &crash, sizeof(bool), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read crash status");
    }

    bool preserve = false;
    if (!ReadFile(pipe, &preserve, sizeof(bool), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read preserve flag");
    }

    SL2_SERVER_LOG_INFO("finalizing %S", run_id_s);

    if (!crash && !preserve) {
        SL2_SERVER_LOG_INFO("no crash, removing run %S", run_id_s);
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
        SL2_SERVER_LOG_INFO("no crash, but not removing files (requested)");
    }
    else {
        SL2_SERVER_LOG_INFO("crash found for run %S", run_id_s);
    }

    RpcStringFree((RPC_WSTR *)&run_id_s);
}

static void handle_get_arena(HANDLE pipe)
{
    DWORD txsize;
    size_t size = 0;
    sl2_arena arena = {0};

    if (!ReadFile(pipe, &size, sizeof(size), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read arena ID size");
    }

    if (size != SL2_HASH_LEN * sizeof(wchar_t)) {
        SL2_SERVER_LOG_FATAL("wrong arena ID size %lu != %lu", size, SL2_HASH_LEN * sizeof(wchar_t));
    }

    if (!ReadFile(pipe, arena.id, (DWORD) size, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read arena ID");
    }

    SL2_SERVER_LOG_INFO("got arena ID: %S", arena.id);

    wchar_t arena_path[MAX_PATH + 1] = {0};

    PathCchCombine(arena_path, MAX_PATH, FUZZ_ARENAS_PATH, arena.id);

    DWORD attrs = GetFileAttributes(arena_path);

    if (attrs == INVALID_FILE_ATTRIBUTES) {
        SL2_SERVER_LOG_INFO("no arena found, creating one");
        dump_arena(arena_path, &arena);
    }
    else {
        SL2_SERVER_LOG_INFO("arena found, loading from disk");
        load_arena(arena_path, &arena);
    }

    if (!WriteFile(pipe, arena.map, FUZZ_ARENA_SIZE, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write arena");
    }
}

static void handle_set_arena(HANDLE pipe)
{
    DWORD txsize;
    size_t size = 0;
    sl2_arena arena = {0};

    if (!ReadFile(pipe, &size, sizeof(size), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read arena ID size");
    }

    if (size != SL2_HASH_LEN * sizeof(wchar_t)) {
        SL2_SERVER_LOG_FATAL("wrong arena ID size %lu != %lu", size, SL2_HASH_LEN * sizeof(wchar_t));
    }

    if (!ReadFile(pipe, arena.id, (DWORD) size, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read arena ID");
    }

    SL2_SERVER_LOG_INFO("got arena ID: %S", arena.id);

    wchar_t arena_path[MAX_PATH + 1] = {0};

    PathCchCombine(arena_path, MAX_PATH, FUZZ_ARENAS_PATH, arena.id);

    if (!ReadFile(pipe, arena.map, FUZZ_ARENA_SIZE, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read arena");
    }

    dump_arena(arena_path, &arena);
}

static void handle_crash_paths(HANDLE pipe)
{
    DWORD txsize;
    UUID run_id;
    wchar_t *run_id_s;

    if (!ReadFile(pipe, &run_id, sizeof(UUID), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read UUID");
    }

    UuidToString(&run_id, (RPC_WSTR *)&run_id_s);

    wchar_t run_dir[MAX_PATH + 1] = {0};
    wchar_t target_file[MAX_PATH + 1] = {0};

    PathCchCombine(run_dir, MAX_PATH, FUZZ_WORKING_PATH, run_id_s);
    PathCchCombine(target_file, MAX_PATH, run_dir, FUZZ_RUN_CRASH_JSON);

    size_t size = lstrlen(target_file) * sizeof(wchar_t);

    if (!WriteFile(pipe, &size, sizeof(size), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write length of crash.json to pipe");
    }

    if (!WriteFile(pipe, &target_file, (DWORD)size, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write crash.json path to pipe");
    }

    memset(target_file, 0, (MAX_PATH + 1) * sizeof(wchar_t));
    PathCchCombine(target_file, MAX_PATH, run_dir, FUZZ_RUN_MEM_DMP);

    size = lstrlen(target_file) * sizeof(wchar_t);

    if (!WriteFile(pipe, &size, sizeof(size), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write length of mem.dmp path to pipe");
    }

    if (!WriteFile(pipe, &target_file, (DWORD)size, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write mem.dmp path to pipe");
    }

    memset(target_file, 0, (MAX_PATH + 1) * sizeof(wchar_t));
    PathCchCombine(target_file, MAX_PATH, run_dir, FUZZ_RUN_INITIAL_DMP);

    size = lstrlen(target_file) * sizeof(wchar_t);

    if (!WriteFile(pipe, &size, sizeof(size), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write length of initial.dmp path to pipe");
    }

    if (!WriteFile(pipe, &target_file, (DWORD)size, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write initial.dmp path to pipe");
    }

    RpcStringFree((RPC_WSTR *)&run_id_s);
}

static void handle_ping(HANDLE pipe)
{
    DWORD txsize;
    uint8_t ok = 1;

    SL2_SERVER_LOG_INFO("ponging the client");

    if (!WriteFile(pipe, &ok, sizeof(ok), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write pong status to pipe");
    }
}

static void destroy_pipe(HANDLE pipe)
{
    if (!FlushFileBuffers(pipe)) {
        SL2_SERVER_LOG_FATAL("failed to flush pipe");
    }

    if (!DisconnectNamedPipe(pipe)) {
        SL2_SERVER_LOG_FATAL("failed to disconnect pipe");
    }

    if (!CloseHandle(pipe)) {
        SL2_SERVER_LOG_FATAL("failed to close pipe");
    }
}

/* Handles incoming connections from clients */
static DWORD WINAPI thread_handler(void *data)
{
    HANDLE pipe = (HANDLE) data;
    DWORD txsize;
    uint8_t event;

    // NOTE(ww): This is a second event loop, inside of the infinite event loop that
    // creates each thread and calls thread_handler. We do this so that clients can
    // re-use their pipe instances to send multiple events -- with only the top-level
    // loop, each connection would be discarded after a single event.
    //
    // To end a "session", a client sends the EVT_SESSION_TEARDOWN event. "Session"
    // is in scare quotes because each session is essentially anonymous -- the server
    // only sees when they end, not which runs or events they correspond to.
    do {
        event = EVT_INVALID;

        SL2_SERVER_LOG_INFO("waiting for the next event!");

        if (!ReadFile(pipe, &event, sizeof(event), &txsize, NULL)) {
            if (GetLastError() != ERROR_BROKEN_PIPE) {
                SL2_SERVER_LOG_FATAL("failed to read event");
            }
            else {
                // Pipe was broken when we tried to read it. Happens when the python client
                // checks if it exists.
                SL2_SERVER_LOG_ERROR("broken pipe! ending session on event=%d", event);
                destroy_pipe(pipe);
                return 0;
            }
        }

        SL2_SERVER_LOG_INFO("got event ID: %d", event);

        // Dispatch individual requests based on which event the client requested
        // TODO(ww): Construct a sl2_conn here, and pass it to each event handler.
        // Then, re-use our length-prefixed read and write utility functions
        // in sl2_server_api.cpp to deduplicate some of the transaction code.
        switch (event) {
            case EVT_RUN_ID:
                handle_generate_run_id(pipe);
                break;
            case EVT_REGISTER_MUTATION:
                handle_register_mutation(pipe);
                break;
            case EVT_CRASH_PATHS:
                handle_crash_paths(pipe);
                break;
            case EVT_REPLAY:
                handle_replay(pipe);
                break;
            case EVT_RUN_COMPLETE:
                handle_finalize_run(pipe);
                break;
            case EVT_GET_ARENA:
                handle_get_arena(pipe);
                break;
            case EVT_SET_ARENA:
                handle_set_arena(pipe);
                break;
            case EVT_PING:
                handle_ping(pipe);
                break;
            case EVT_SESSION_TEARDOWN:
                SL2_SERVER_LOG_INFO("ending a client's session with the server.");
                break;
            case EVT_MUTATION:
            case EVT_RUN_INFO:
            case EVT_CRASH_PATH:
            case EVT_MEM_DMP_PATH:
                SL2_SERVER_LOG_ERROR("deprecated event requested.");
                event = EVT_INVALID;
                break;
            default:
                SL2_SERVER_LOG_ERROR("unknown or invalid event %d", event);
                break;
        }
    } while (event != EVT_SESSION_TEARDOWN && event != EVT_INVALID);

    SL2_SERVER_LOG_INFO("closing pipe after event=%d", event);
    destroy_pipe(pipe);

    return 0;
}

// Init dirs and create a new thread to handle input from the named pipe
int main(int argvc, char **argv)
{
    init_logging_path();
    loguru::init(argvc, argv);
    char log_path_mbs[MAX_PATH + 1]= {0};
    wcstombs_s(NULL, log_path_mbs, MAX_PATH, FUZZ_LOG, MAX_PATH);
    loguru::add_file(log_path_mbs, loguru::Append, loguru::Verbosity_MAX);

    std::atexit(server_cleanup);

    init_working_paths();

    SL2_SERVER_LOG_INFO("server started!");

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
            SL2_SERVER_LOG_FATAL("could not create pipe");
        }

        bool connected = ConnectNamedPipe(pipe, NULL) ?
            true : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (connected) {
            HANDLE thread = CreateThread(
                NULL,
                0,
                thread_handler,
                (void *) pipe,
                0,
                NULL);

            if (thread == NULL)
            {
                SL2_SERVER_LOG_FATAL("CreateThread failed\n");
            }
            else {
                CloseHandle(thread);
            }
        }
        else {
            SL2_SERVER_LOG_ERROR("could not connect to pipe");
            CloseHandle(pipe);
        }
    }

    return 0;
}
