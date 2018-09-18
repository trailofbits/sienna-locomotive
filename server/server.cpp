#include <map>
#include <cstdlib>
#include <mutex>
#include <shared_mutex>
#include <cstring>
#include <cstdio>

#define NOMINMAX
#include <Windows.h>
#include <Tlhelp32.h>
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
#include "vendor/picosha2.h"
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

struct strategy_state {
    sl2_arena arena;
    uint32_t score;
    uint32_t strategy;
    uint32_t tries_remaining;
    std::map<uint32_t, int64_t> success_map;
};

struct server_opts {
    bool dump_mut_buffer;
    bool pinned;
    bool bucketing;
    uint32_t stickiness;
};

typedef std::map<std::wstring, strategy_state> sl2_strategy_map_t;

static server_opts opts = {0};

// TODO(ww): Replace these with std::shared_mutex.
static CRITICAL_SECTION pid_lock;
static CRITICAL_SECTION fkt_lock;
static CRITICAL_SECTION arena_lock;
static HANDLE process_mutex = INVALID_HANDLE_VALUE;

static wchar_t FUZZ_WORKING_PATH[MAX_PATH] = L"";
static wchar_t FUZZ_ARENAS_PATH[MAX_PATH] = L"";
static wchar_t FUZZ_LOG[MAX_PATH] = L"";

static std::shared_mutex strategy_mutex;
static sl2_strategy_map_t strategy_map;

// Gets the processor affinity mask for the given process ID.
static bool get_process_affinity(uint32_t pid, uint64_t *mask)
{
    HANDLE handle;
    uint64_t system_affinity;

    if (!(handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid))) {
        SL2_SERVER_LOG_WARN("couldn't open process for pid=%d", pid);
        *mask = -1;
        return false;
    }

    if (!GetProcessAffinityMask(handle, mask, &system_affinity)) {
        SL2_SERVER_LOG_WARN("couldn't get process affinity for pid=%d", pid);
        *mask = -1;
        return false;
    }

    CloseHandle(handle);

    return true;
}

// Finds the first free processor, i.e. the first processor
// that doesn't already have a process pinned to it.
static bool find_free_processor(uint64_t *mask)
{
    uint64_t cpu_mask = 0;
    PROCESSENTRY32 process_entry;
    HANDLE snapshot;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        SL2_SERVER_LOG_FATAL("failed to snapshot process!");
    }

    process_entry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &process_entry)) {
        CloseHandle(snapshot);
        SL2_SERVER_LOG_FATAL("failed to enumerate processes!");
    }

    do {
        uint64_t affinity;

        // If we weren't able to get the process's affinity, keep looking.
        if (!get_process_affinity(process_entry.th32ProcessID, &affinity)) {
            continue;
        }

        // NOTE(ww): WinAFL discards masks that have more than two processors set,
        // which doesn't make sense to me.
        cpu_mask |= affinity;
    } while (Process32Next(snapshot, &process_entry));

    for (int i = 0; i < 64; ++i) {
        if (!((cpu_mask >> i) & 1)) {
            *mask = 0;
            *mask |= (1 << i);
            return true;
        }
    }

    return false;

    CloseHandle(snapshot);
}

// Pins the server's process to the first free processor.
static bool pin_to_free_processor()
{
    SYSTEM_INFO info = {0};
    uint64_t free_mask;

    GetSystemInfo(&info);

    if (info.dwNumberOfProcessors < 2) {
        SL2_SERVER_LOG_INFO("nprocessors=%d < 2, not bothing to pin to a processor", info.dwNumberOfProcessors);
        return true;
    }

    if (info.dwNumberOfProcessors > 64) {
        SL2_SERVER_LOG_WARN("nprocessors=%d > 64, processor pinning not supported!", info.dwNumberOfProcessors);
        return false;
    }

    if (!find_free_processor(&free_mask)) {
        SL2_SERVER_LOG_WARN("couldn't find a free processor!");
        return false;
    }

    if (!SetProcessAffinityMask(GetCurrentProcess(), free_mask)) {
        return false;
    }

    return true;
}

// Scores the coverage of the given arena by placing
// hit counts into buckets: higher scores are given
// for relatively small counts, while large counts
// are given lower scores.
static uint32_t bucket_score(sl2_arena *arena)
{
    uint32_t score = 0;

    for (int i = 0; i < FUZZ_ARENA_SIZE; ++i) {
        if (!arena->map[i]) {
            continue;
        }

        if (arena->map[i] <= 3) {
            score += 32;
        }
        else if (arena->map[i] <= 7) {
            score += 16;
        }
        else if (arena->map[i] <= 15) {
            score += 8;
        }
        else if (arena->map[i] <= 31) {
            score += 4;
        }
        else if (arena->map[i] <= 127) {
            score += 2;
        }
        else {
            score += 1;
        }
    }

    return score;
}

// Scores the coverage of the given arena with
// a dumb hit counter: the ultimate score
// is the number of nonzero cells in the arena.
static uint32_t coverage_count(sl2_arena *arena)
{
    uint32_t score = 0;

    for (int i = 0; i < FUZZ_ARENA_SIZE; ++i) {
        if (arena->map[i]) {
            score++;
        }
    }

    return score;
}

static uint32_t coverage_score(sl2_arena *arena)
{
    if (opts.bucketing) {
        return bucket_score(arena);
    }

    return coverage_count(arena);
}

/* concurrency protection */
static void lock_process()
{
    process_mutex = CreateMutex(NULL, false, L"fuzz_server_mutex");
    if (!process_mutex || process_mutex == INVALID_HANDLE_VALUE) {
        SL2_SERVER_LOG_FATAL("could not create process lock");
    }

    // Give ourselves a few milliseconds to acquire the mutex from the harness.
    DWORD result = WaitForSingleObject(process_mutex, 10);
    if (result != WAIT_OBJECT_0) {
        SL2_SERVER_LOG_FATAL("could not obtain process lock");
    }
}

// Called on process termination (by atexit).
static void server_cleanup()
{
    SL2_SERVER_LOG_INFO("cleaning things up");

    // NOTE(ww): We could probably check return codes here, but there's
    // no point -- the process is about to be destroyed anyways.
    ReleaseMutex(process_mutex);
    CloseHandle(process_mutex);
    DeleteCriticalSection(&pid_lock);
    DeleteCriticalSection(&fkt_lock);
    DeleteCriticalSection(&arena_lock);
}

// Called on session termination.
static void destroy_pipe(HANDLE pipe)
{
    if (!FlushFileBuffers(pipe)) {
        SL2_SERVER_LOG_ERROR("failed to flush pipe");
    }

    if (!DisconnectNamedPipe(pipe)) {
        SL2_SERVER_LOG_ERROR("failed to disconnect pipe");
    }

    if (!CloseHandle(pipe)) {
        SL2_SERVER_LOG_ERROR("failed to close pipe");
    }
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
static uint8_t write_fkt(wchar_t *target_file, uint32_t type, uint32_t mutation_type, size_t resource_size, wchar_t *resource_path, size_t position, size_t size, uint8_t* buf)
{
    uint8_t rc = 0;
    DWORD txsize;

    EnterCriticalSection(&fkt_lock);

    HANDLE fkt = CreateFile(target_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    if (fkt == INVALID_HANDLE_VALUE) {
        SL2_SERVER_LOG_ERROR("failed to create FTK: %S", target_file);
        rc = 1;
        goto cleanup;
    }

    if (!WriteFile(fkt, "FKT\0", 4, &txsize, NULL)) {
        SL2_SERVER_LOG_ERROR("failed to write FKT header");
        rc = 1;
        goto cleanup;
    }

    if (!WriteFile(fkt, &type, sizeof(type), &txsize, NULL)) {
        SL2_SERVER_LOG_ERROR("failed to write type");
        rc = 1;
        goto cleanup;
    }

    if (!WriteFile(fkt, &mutation_type, sizeof(mutation_type), &txsize, NULL)) {
        SL2_SERVER_LOG_ERROR("failed to write mutation type");
        rc = 1;
        goto cleanup;
    }

    if (!WriteFile(fkt, &resource_size, sizeof(resource_size), &txsize, NULL)) {
        SL2_SERVER_LOG_ERROR("failed to write path size");
        rc = 1;
        goto cleanup;
    }

    if (!WriteFile(fkt, resource_path, (DWORD) (resource_size * sizeof(wchar_t)), &txsize, NULL)) {
        SL2_SERVER_LOG_ERROR("failed to write path");
        rc = 1;
        goto cleanup;
    }

    if (!WriteFile(fkt, &position, sizeof(position), &txsize, NULL)) {
        SL2_SERVER_LOG_ERROR("failed to write offset");
        rc = 1;
        goto cleanup;
    }

    if (!WriteFile(fkt, &size, sizeof(size_t), &txsize, NULL)) {
        SL2_SERVER_LOG_ERROR("failed to write buffer size");
        rc = 1;
        goto cleanup;
    }

    if (!WriteFile(fkt, buf, (DWORD)size, &txsize, NULL)) {
        SL2_SERVER_LOG_ERROR("failed to write buffer");
        rc = 1;
        goto cleanup;
    }

    if (!CloseHandle(fkt)) {
        SL2_SERVER_LOG_ERROR("failed to close FKT");
        rc = 1;
        goto cleanup;
    }

    cleanup:

    LeaveCriticalSection(&fkt_lock);
    return rc;
}

/* Gets the mutated bytes stored in the FKT file for mutation replay */
static void get_bytes_fkt(wchar_t *target_file, uint8_t *buf, size_t size)
{
    DWORD txsize;
    size_t buf_size = 0;

    EnterCriticalSection(&fkt_lock);

    HANDLE fkt = CreateFile(target_file, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (fkt == INVALID_HANDLE_VALUE) {
        SL2_SERVER_LOG_FATAL("failed to open FKT: %S", target_file);
    }

    // TODO(ww): We shouldn't be hardcoding this offset.
    SetFilePointer(fkt, 0x1c, NULL, FILE_BEGIN);
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

    LeaveCriticalSection(&fkt_lock);
}

static void dump_arena_to_disk(wchar_t *arena_path, sl2_arena *arena)
{
    EnterCriticalSection(&arena_lock);

    DWORD txsize;
    HANDLE file = CreateFile(
        arena_path,
        GENERIC_WRITE,
        0, NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (file != INVALID_HANDLE_VALUE) {
        if (!WriteFile(file, arena->map, FUZZ_ARENA_SIZE, &txsize, NULL)) {
            SL2_SERVER_LOG_FATAL("failed to write arena to disk!");
        }

        if (txsize != FUZZ_ARENA_SIZE) {
            SL2_SERVER_LOG_FATAL("(txsize=%lu) != (FUZZ_ARENA_SIZE=%lu), truncated write?", txsize, FUZZ_ARENA_SIZE);
        }

        if (!CloseHandle(file)) {
            SL2_SERVER_LOG_ERROR("failed to close arena (arena_path=%S)", arena_path);
        }
    }
    else {
        SL2_SERVER_LOG_ERROR("failed to open arena_path=%S, skipping dump!", arena_path);
    }

    LeaveCriticalSection(&arena_lock);
}

static bool load_arena_from_disk(wchar_t *arena_path, sl2_arena *arena)
{
    bool rc = true;
    DWORD txsize;

    EnterCriticalSection(&arena_lock);

    HANDLE file = CreateFile(
        arena_path,
        GENERIC_READ,
        0, NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (file == INVALID_HANDLE_VALUE) {
        SL2_SERVER_LOG_ERROR("failed to open arena (arena_path=%S)", arena_path);
        rc = false;
        goto cleanup;
    }

    if (!ReadFile(file, arena->map, FUZZ_ARENA_SIZE, &txsize, NULL)) {
        SL2_SERVER_LOG_ERROR("failed to read arena from disk!");
        rc = false;
        goto cleanup;
    }

    if (txsize != FUZZ_ARENA_SIZE) {
        SL2_SERVER_LOG_ERROR("(txsize=%lu) != (FUZZ_ARENA_SIZE=%lu), truncated read?", txsize, FUZZ_ARENA_SIZE);
        rc = false;
        goto cleanup;
    }

    if (!CloseHandle(file)) {
        SL2_SERVER_LOG_ERROR("failed to close arena (arena_path=%S)", arena_path);
        rc = false;
        goto cleanup;
    }

    cleanup:

    LeaveCriticalSection(&arena_lock);

    return rc;
}

static void handle_register_mutation(HANDLE pipe)
{
    DWORD txsize;
    UUID run_id;
    wchar_t *run_id_s;
    uint8_t status = 0;

    SL2_SERVER_LOG_INFO("starting mutation registration");

    if (!ReadFile(pipe, &run_id, sizeof(run_id), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read run ID");
    }

    if (UuidToString(&run_id, (RPC_WSTR *)&run_id_s) != RPC_S_OK) {
        SL2_SERVER_LOG_FATAL("couldn't stringify UUID");
    }

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

    uint32_t mutation_type = 0;
    if (!ReadFile(pipe, &mutation_type, sizeof(mutation_type), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read mutation type");
    }

    size_t resource_size = 0;
    if (!ReadFile(pipe, &resource_size, sizeof(resource_size), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read size of mutation filepath");
    }

    wchar_t resource_path[MAX_PATH + 1] = {0};
    if (resource_size >= (MAX_PATH * sizeof(wchar_t))) {
        // TODO(ww): Instead of failing, maybe just truncate here?
        SL2_SERVER_LOG_FATAL("resource_size >= MAX_PATH");
    }

    // NOTE(ww): Interestingly, Windows distinguishes between a read of 0 bytes
    // and no read at all -- both the client and the server have to do either one or the
    // other, and failing to do either on one side causes a truncated read or write.
    if (resource_size > 0) {
        if (!ReadFile(pipe, &resource_path, (DWORD) resource_size, &txsize, NULL)) {
            SL2_SERVER_LOG_FATAL("failed to read mutation filepath");
        }

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

    if (size > 0) {
        uint8_t *buf = (uint8_t *) malloc(size);

        if (buf == NULL) {
            SL2_SERVER_LOG_ERROR("failed to allocate mutation buffer (size=%lu)", size);
            status = 1;
            goto cleanup;
        }

        if (!ReadFile(pipe, buf, (DWORD)size, &txsize, NULL)) {
            SL2_SERVER_LOG_ERROR("failed to read mutation buffer from pipe (size=%lu)", size);
            free(buf);
            status = 1;
            goto cleanup;
        }

        if (txsize < size) {
            SL2_SERVER_LOG_WARN("read fewer bytes than expected (%d < %lu)", txsize, size);
            size = txsize;
        }

        wchar_t run_dir[MAX_PATH + 1] = {0};
        wchar_t target_file[MAX_PATH + 1] = {0};

        PathCchCombine(run_dir, MAX_PATH, FUZZ_WORKING_PATH, run_id_s);
        PathCchCombine(target_file, MAX_PATH, run_dir, mutate_fname);

        status = write_fkt(target_file, type, mutation_type, resource_size, resource_path, position, size, buf);

        if (opts.dump_mut_buffer) {
            SL2_SERVER_LOG_INFO("mutation buffer dump requested");

            memset(target_file, 0, (MAX_PATH + 1) * sizeof(wchar_t));
            PathCchCombine(target_file, MAX_PATH, run_dir, L"buffer.bin");

            HANDLE file = CreateFile(target_file,
                GENERIC_WRITE,
                0, NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL);

            if (file != INVALID_HANDLE_VALUE) {
                WriteFile(file, buf, size, &txsize, NULL);
                CloseHandle(file);
            }
            else {
                SL2_SERVER_LOG_ERROR("couldn't create buffer dump file?");
            }
        }

        free(buf);
    }
    else {
        SL2_SERVER_LOG_WARN("got size=%lu, skipping registration", size);
    }

    cleanup:

    if (!WriteFile(pipe, &status, sizeof(status), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write server status");
    }

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

    if (UuidToString(&run_id, (RPC_WSTR *)&run_id_s) != RPC_S_OK) {
        SL2_SERVER_LOG_FATAL("couldn't stringify UUID");
    }

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
        SL2_SERVER_LOG_FATAL("missing FKT or is a directory: %S", target_file);
    }

    get_bytes_fkt(target_file, buf, size);

    if (!WriteFile(pipe, buf, (DWORD) size, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write replay buffer");
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

    // If we already have the arena in our strategy map, then we don't
    // need to load it from disk again.
    // Otherwise, we attempt to load the arena from disk, creating it if we don't
    // have one, and then add it to our strategy map.
    std::unique_lock<std::shared_mutex> strategy_lock(strategy_mutex);
    sl2_strategy_map_t::iterator it = strategy_map.find(arena.id);

    if (it != strategy_map.end()) {
        memcpy_s(arena.map, FUZZ_ARENA_SIZE, it->second.arena.map, FUZZ_ARENA_SIZE);
    }
    else {
        wchar_t arena_path[MAX_PATH + 1] = {0};

        PathCchCombine(arena_path, MAX_PATH, FUZZ_ARENAS_PATH, arena.id);

        DWORD attrs = GetFileAttributes(arena_path);

        if (attrs == INVALID_FILE_ATTRIBUTES) {
            SL2_SERVER_LOG_INFO("no arena found, creating one");
            dump_arena_to_disk(arena_path, &arena);
        }
        else {
            SL2_SERVER_LOG_INFO("arena found, loading from disk");

            if (!load_arena_from_disk(arena_path, &arena)) {
                SL2_SERVER_LOG_ERROR("load_arena_from_disk failed, resetting the arena");
                dump_arena_to_disk(arena_path, &arena);
            }
        }

        uint32_t score = coverage_score(&arena);

        SL2_SERVER_LOG_INFO("score=%d", score);

        // NOTE(ww): Start at strategy #0, because why not.
        // In the future, we should grab the last strategy tried
        // from the FKT and start with that.
        strategy_map[arena.id] = { arena, score, 0, opts.stickiness };
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

    std::unique_lock<std::shared_mutex> strategy_lock(strategy_mutex);
    sl2_strategy_map_t::iterator it = strategy_map.find(arena.id);

    // This should never happen, as the fuzzer always requests an arena before sending one back.
    if (it == strategy_map.end()) {
        SL2_SERVER_LOG_FATAL("no prior arena to compare against! fuzzer didn't request an initial arena?");
    }

    strategy_state prior = it->second;

    // Record a raw copy of the coverage map for path identification
    wchar_t wcs[SL2_HASH_LEN + 3];
    wcscpy_s(wcs, L"R_");
    wcscat_s(wcs, arena.id);
    strategy_map[wcs] = { arena, coverage_score(&arena), prior.strategy, opts.stickiness, prior.success_map };

    // Merge the existing coverage map with the one returned from the fuzzer
    for(int i = 0; i < FUZZ_ARENA_SIZE; i++){
        arena.map[i] += strategy_map[arena.id].arena.map[i];
    }

    uint32_t score = coverage_score(&arena);

    SL2_SERVER_LOG_INFO("score=%d, prior.score=%d", score, prior.score);

    // If coverage has increased, continue with the current strategy
    // and reset the number of remaining tries.
    //
    // Otherwise, try a new strategy.
    if (score > prior.score) {
        SL2_SERVER_LOG_INFO("coverage score increased, continuing with strategy=%d", prior.strategy);

        prior.success_map[prior.strategy]++;
        strategy_map[arena.id] = { arena, score, prior.strategy, opts.stickiness, prior.success_map };
    }
    else {
        SL2_SERVER_LOG_INFO("coverage score did NOT increase!");

        // If we've run out of tries for this strategy, move to a new one
        // (and reset the number of tries).
        //
        // Otherwise, try again, and decrement the number of tries remaining.
        if (prior.tries_remaining <= 0) {
            uint32_t strategy;

            // Ignore the success map about 20% of the time, to make sure that
            // we're not digging ourselves into a hole.
            //
            // Otherwise, grab the best strategy from the strategy map.
            if (!(rand() % 5)) {
                strategy = (prior.strategy + 1) % SL2_NUM_STRATEGIES;
            }
            else {
                bool found_success = false;
                strategy = 0;

                for (int i = 1; i < SL2_NUM_STRATEGIES; ++i) {
                    if (prior.success_map[strategy] < prior.success_map[i]
                        && prior.strategy != i) {
                        strategy = i;
                        found_success = true;
                    }
                }

                // Fallback: We've seen no successful strategies (other than the current one),
                // so just move on.
                if (!found_success) {
                    strategy = (prior.strategy + 1) % SL2_NUM_STRATEGIES;
                }
            }

            SL2_SERVER_LOG_INFO("no tries left, changing strategy (%d)!", strategy);

            prior.success_map[prior.strategy]--;
            strategy_map[arena.id] = { arena, score, strategy, opts.stickiness, prior.success_map };
        }
        else {
            SL2_SERVER_LOG_INFO("%d tries for strategy %d left", prior.tries_remaining - 1, prior.strategy);

            strategy_map[arena.id] = { arena, score, prior.strategy, prior.tries_remaining - 1, prior.success_map };
        }
    }

    // TODO(ww): We should try to avoid/minimize dumping the arena to disk.
    dump_arena_to_disk(arena_path, &arena);
}

static void handle_crash_paths(HANDLE pipe)
{
    DWORD txsize;
    UUID run_id;
    wchar_t *run_id_s;
    uint64_t pid;

    if (!ReadFile(pipe, &run_id, sizeof(run_id), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read UUID");
    }

    if (UuidToString(&run_id, (RPC_WSTR *)&run_id_s) != RPC_S_OK) {
        SL2_SERVER_LOG_FATAL("couldn't stringify UUID");
    }

    if (!ReadFile(pipe, &pid, sizeof(pid), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read PID");
    }

    wchar_t run_dir[MAX_PATH + 1] = {0};
    wchar_t target_file[MAX_PATH + 1] = {0};
    wchar_t target_path[MAX_PATH + 1] = {0};

    PathCchCombine(run_dir, MAX_PATH, FUZZ_WORKING_PATH, run_id_s);
    StringCchPrintfW(target_file, MAX_PATH, FUZZ_RUN_CRASH_JSON_FMT, pid);
    PathCchCombine(target_path, MAX_PATH, run_dir, target_file);

    size_t size = wcsnlen_s(target_path, MAX_PATH + 1) * sizeof(wchar_t);

    if (!WriteFile(pipe, &size, sizeof(size), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write length of crash.json to pipe");
    }

    if (!WriteFile(pipe, &target_path, (DWORD)size, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write crash.json path to pipe");
    }

    memset(target_file, 0, (MAX_PATH + 1) * sizeof(wchar_t));
    memset(target_path, 0, (MAX_PATH + 1) * sizeof(wchar_t));
    StringCchPrintfW(target_file, MAX_PATH, FUZZ_RUN_MEM_DMP_FMT, pid);
    PathCchCombine(target_path, MAX_PATH, run_dir, target_file);

    size = wcsnlen_s(target_path, MAX_PATH + 1) * sizeof(wchar_t);

    if (!WriteFile(pipe, &size, sizeof(size), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write length of mem.dmp path to pipe");
    }

    if (!WriteFile(pipe, &target_path, (DWORD)size, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write mem.dmp path to pipe");
    }

    memset(target_file, 0, (MAX_PATH + 1) * sizeof(wchar_t));
    memset(target_path, 0, (MAX_PATH + 1) * sizeof(wchar_t));
    StringCchPrintfW(target_file, MAX_PATH, FUZZ_RUN_INITIAL_DMP_FMT, pid);
    PathCchCombine(target_path, MAX_PATH, run_dir, target_file);

    size = wcsnlen_s(target_path, MAX_PATH + 1) * sizeof(wchar_t);

    if (!WriteFile(pipe, &size, sizeof(size), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write length of initial.dmp path to pipe");
    }

    if (!WriteFile(pipe, &target_path, (DWORD)size, &txsize, NULL)) {
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

static void handle_register_pid(HANDLE pipe)
{
    DWORD txsize;
    UUID run_id;
    wchar_t *run_id_s;
    bool tracing;
    uint64_t pid;

    SL2_SERVER_LOG_INFO("received pid registration request");

    if (!ReadFile(pipe, &run_id, sizeof(run_id), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read UUID");
    }

    if (!ReadFile(pipe, &tracing, sizeof(tracing), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read tracing/fuzzing flag");
    }

    if (!ReadFile(pipe, &pid, sizeof(pid), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read pid");
    }

    SL2_SERVER_LOG_INFO("got pid=%lu", pid);

    if (UuidToString(&run_id, (RPC_WSTR *)&run_id_s) != RPC_S_OK) {
        SL2_SERVER_LOG_FATAL("couldn't stringify UUID");
    }

    wchar_t run_dir[MAX_PATH + 1] = {0};
    wchar_t pids_file[MAX_PATH + 1] = {0};
    wchar_t pid_s[64] = {0};

    _ui64tow_s(pid, pid_s, sizeof(pid_s) - 1, 10);
    pid_s[wcsnlen_s(pid_s, sizeof(pid_s))] = '\n';

    PathCchCombine(run_dir, MAX_PATH, FUZZ_WORKING_PATH, run_id_s);
    PathCchCombine(pids_file, MAX_PATH, run_dir, tracing ? FUZZ_RUN_TRACER_PIDS
                                                         : FUZZ_RUN_FUZZER_PIDS);

    RpcStringFree((RPC_WSTR *)&run_id_s);

    EnterCriticalSection(&pid_lock);

    HANDLE file = CreateFile(
        pids_file,
        FILE_APPEND_DATA,
        0, NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (file != INVALID_HANDLE_VALUE) {
        if (!WriteFile(file, pid_s, (DWORD) wcsnlen_s(pid_s, sizeof(pid_s)) * sizeof(wchar_t), &txsize, NULL)) {
            SL2_SERVER_LOG_ERROR("failed to write pid (pid=%lu, pids_file=%S)", pid, pids_file);
        }

        if (!CloseHandle(file)) {
            SL2_SERVER_LOG_ERROR("failed to close pids_file=%S", pids_file);
        }
    }
    else {
        SL2_SERVER_LOG_ERROR("failed to open pids_file=%S, not recording pid!", pids_file);
    }

    LeaveCriticalSection(&pid_lock);
}

static void handle_advise_mutation(HANDLE pipe)
{
    DWORD txsize;
    size_t size;
    wchar_t arena_id[SL2_HASH_LEN + 1] = {0};
    uint32_t table_idx = 0;

    if (!ReadFile(pipe, &size, sizeof(size), &txsize, NULL))  {
        SL2_SERVER_LOG_FATAL("failed to read arena ID size");
    }

    if (size != SL2_HASH_LEN * sizeof(wchar_t)) {
        SL2_SERVER_LOG_FATAL("wrong arena ID size %lu != %lu", size, SL2_HASH_LEN * sizeof(wchar_t));
    }

    if (!ReadFile(pipe, &arena_id, (DWORD) size, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read arena ID");
    }

    SL2_SERVER_LOG_INFO("got arena ID: %S", arena_id);

    std::unique_lock<std::shared_mutex> strategy_lock(strategy_mutex);
    sl2_strategy_map_t::iterator it = strategy_map.find(arena_id);

    if (it == strategy_map.end()) {
        SL2_SERVER_LOG_FATAL("arena ID missing from strategy_map? (map size=%d)", strategy_map.size());
    }

    table_idx = it->second.strategy;
    if (!WriteFile(pipe, &table_idx, sizeof(table_idx), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write strategy advice");
    }
}

static void handle_coverage_info(HANDLE pipe)
{
    DWORD txsize;
    size_t size;
    wchar_t arena_id[SL2_HASH_LEN + 1] = {0};

    if (!ReadFile(pipe, &size, sizeof(size), &txsize, NULL))  {
        SL2_SERVER_LOG_FATAL("failed to read arena ID size");
    }

    if (size != SL2_HASH_LEN * sizeof(wchar_t)) {
        SL2_SERVER_LOG_FATAL("wrong arena ID size %lu != %lu", size, SL2_HASH_LEN * sizeof(wchar_t));
    }

    if (!ReadFile(pipe, &arena_id, (DWORD) size, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to read arena ID");
    }

    SL2_SERVER_LOG_INFO("got arena ID: %S", arena_id);
    wchar_t raw_arena_id[SL2_HASH_LEN + 3] = {0};
    wcscpy(raw_arena_id, L"R_");
    wcscat(raw_arena_id, arena_id);

    std::unique_lock<std::shared_mutex> strategy_lock(strategy_mutex);
    sl2_strategy_map_t::iterator it = strategy_map.find(arena_id);

    if (it == strategy_map.end()) {
        SL2_SERVER_LOG_FATAL("arena ID missing from strategy_map? (map size=%d)", strategy_map.size());
    }

    sl2_arena arena = it->second.arena;

    it = strategy_map.find(raw_arena_id);
    if (it == strategy_map.end()) {
        SL2_SERVER_LOG_FATAL("Raw arena ID missing from strategy_map? (map size=%d)", strategy_map.size());
    }
    sl2_arena raw_arena = it->second.arena;

    std::string hash_hex_str = picosha2::hash256_hex_string((unsigned char *)&raw_arena.map, (unsigned char *)&raw_arena.map + FUZZ_ARENA_SIZE);

    // Zeroeth, write the hash of the path.
    if (!WriteFile(pipe, hash_hex_str.c_str(), 64, &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write path hash");
    }

    // First, write whether we're doing bucketing.
    if (!WriteFile(pipe, &opts.bucketing, sizeof(opts.bucketing), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write bucketing status");
    }

    // Then, write our current coverage score for the arena.
    if (!WriteFile(pipe, &(it->second.score), sizeof(it->second.score), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write coverage score");
    }

    // Then, write the number of tries remaining for the current strategy.
    if (!WriteFile(pipe, &(it->second.tries_remaining), sizeof(it->second.tries_remaining), &txsize, NULL)) {
        SL2_SERVER_LOG_FATAL("failed to write number of tries remaining");
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
                SL2_SERVER_LOG_WARN("broken pipe! ending session on event=%d", event);
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
            case EVT_REGISTER_MUTATION:
                handle_register_mutation(pipe);
                break;
            case EVT_CRASH_PATHS:
                handle_crash_paths(pipe);
                break;
            case EVT_REPLAY:
                handle_replay(pipe);
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
            case EVT_REGISTER_PID:
                handle_register_pid(pipe);
                break;
            case EVT_ADVISE_MUTATION:
                handle_advise_mutation(pipe);
                break;
            case EVT_COVERAGE_INFO:
                handle_coverage_info(pipe);
                break;
            case EVT_SESSION_TEARDOWN:
                SL2_SERVER_LOG_INFO("ending a client's session with the server.");
                break;
            // NOTE(ww): These are just here for completeness.
            // Any client that requests them and expects anything back is
            // almost certain to misbehave.
            case EVT_RUN_ID:
            case EVT_MUTATION:
            case EVT_RUN_INFO:
            case EVT_CRASH_PATH:
            case EVT_MEM_DMP_PATH:
            case EVT_RUN_COMPLETE:
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
int main(int argc, char **argv)
{
    init_logging_path();
    loguru::init(argc, argv);
    char log_path_mbs[MAX_PATH + 1]= {0};
    wcstombs_s(NULL, log_path_mbs, MAX_PATH, FUZZ_LOG, MAX_PATH);
    loguru::add_file(log_path_mbs, loguru::Append, loguru::Verbosity_MAX);

    lock_process();
    std::atexit(server_cleanup);

    SL2_SERVER_LOG_INFO("server started!");



    for (int i = 0; i < argc; ++i) {
        if (STREQ(argv[i], "-s")) {
            if (i < argc - 1) {
                opts.stickiness = atoi(argv[i + 1]);
            }
            else {
                SL2_SERVER_LOG_WARN("expected number after -s, none given?");
            }
        }
        else if (STREQ(argv[i], "-b")) {
            opts.bucketing = true;
        }
        else if (STREQ(argv[i], "-p")) {
            opts.pinned = true;
        }
        else if (STREQ(argv[i], "-d")) {
            opts.dump_mut_buffer = true;
        }
    }

    if (opts.pinned && !pin_to_free_processor()) {
        SL2_SERVER_LOG_WARN("failed to pin server to a free processor, too many jobs already pinned?");
    }

    init_working_paths();

    SL2_SERVER_LOG_INFO("dump_mut_buffer=%d, pinned=%d, bucketing=%d, stickiness=%d",
        opts.dump_mut_buffer, opts.pinned, opts.bucketing, opts.stickiness);

    InitializeCriticalSection(&pid_lock);
    InitializeCriticalSection(&fkt_lock);
    InitializeCriticalSection(&arena_lock);

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

            if (thread == NULL) {
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
