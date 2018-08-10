#ifndef SL2_SERVER_HPP
#define SL2_SERVER_HPP

#include "common/util.h"

// The path to the local named pipe, used by the server to communicate with clients.
#define FUZZ_SERVER_PATH (L"\\\\.\\pipe\\fuzz_server")

// The file (under the run directory) in which the name of the program is stored.
#define FUZZ_RUN_PROGRAM_TXT (L"program.txt")

// The file (under the run directory) in which the arguments to the program are stored.
#define FUZZ_RUN_ARGUMENTS_TXT (L"arguments.txt")

// The file (under the run directory) in which the program's execution trace is stored.
#define FUZZ_RUN_EXECUTION_TRC (L"execution.trc")

// The format for files (under the run directory) in which the program's memory dump is stored.
#define FUZZ_RUN_MEM_DMP_FMT (L"mem.%lu.dmp")

// The format for files (under the run directory) in which the program's initial minidump is stored.
#define FUZZ_RUN_INITIAL_DMP_FMT (L"initial.%lu.dmp")

// The file (under the run directory) in which the program's crash state is stored.
#define FUZZ_RUN_EXECUTION_CSH (L"execution.csh")

// The format for files (under the run directory) in which the program's crash triage info is stored.
#define FUZZ_RUN_CRASH_JSON_FMT (L"crash.%lu.json")

// The format for files (under a run directory) containing replayable mutations.
#define FUZZ_RUN_FKT_FMT (L"%d.fkt")

// The file (under the run directory) in which the program's fuzzing pid(s) are stored.
#define FUZZ_RUN_FUZZER_PIDS (L"fuzz.pids")

// The file (under the run directory) in which the program's tracing pid(s) are stored.
#define FUZZ_RUN_TRACER_PIDS (L"trace.pids")

// The size, in bytes, of our fuzzing arena.
#define FUZZ_ARENA_SIZE 65536

enum Event {
    // Request a new run ID from the server.
    // NOTE(ww): Deprecated; the server will complain and may die if you send this.
    EVT_RUN_ID,             // 0
    // Request a mutation from the server.
    // NOTE(ww): Deprecated; the server will complain and may die if you send this.
    EVT_MUTATION,           // 1
    // Request a replay from the server.
    EVT_REPLAY,             // 2
    // Request information about a run from the server.
    // NOTE(ww): Deprecated; the server will complain and may die if you send this.
    EVT_RUN_INFO,           // 3
    // Tell the server to finalize a run.
    // NOTE(ww): Deprecated; the server will complain and may die if you send this.
    EVT_RUN_COMPLETE,       // 4
    // Request a pathname for storing crash information from the server.
    // NOTE(ww): Deprecated; the server will complain and may die if you send this.
    EVT_CRASH_PATH,         // 5
    // Tell the server to end its session with this client.
    EVT_SESSION_TEARDOWN,   // 6
    // Request a pathname for storing a memory dump from the server.
    // NOTE(ww): Deprecated; the server will complain and may die if you send this.
    EVT_MEM_DMP_PATH,       // 7
    // Register a mutation generated by the fuzzer with the server.
    EVT_REGISTER_MUTATION,  // 8
    // Request any and all paths containing crash information from the server.
    EVT_CRASH_PATHS,        // 9
    // Request the coverage arena for a given run.
    EVT_GET_ARENA,          // 10
    // Register the (modified) coverage arena for a given run.
    EVT_SET_ARENA,          // 11
    // Ping the server. Debugging only.
    EVT_PING,               // 12
    // Tell the server about a pid associated with a fuzzing or tracing run.
    EVT_REGISTER_PID,       // 13
    // Use this as a default value when handling multiple events.
    // NOTE(ww): The server will complain and may die if you send this.
    EVT_INVALID = 255,
};

// Represents the state associated with a mutation, including
// the function whose input has been mutated, the mutation count,
// the resource behind the mutation, the position within the resource,
// the size of the mutated buffer, and the mutated buffer itself.
//
// May represent the state *before* a mutation, meaning that `buffer` has not
// changed yet.
struct sl2_mutation {
    uint32_t function;
    uint32_t mut_count;
    uint32_t mut_type;
    wchar_t *resource;
    size_t position;
    size_t bufsize;
    uint8_t *buffer;
};

// A structure containing valid pathnames for storage
// of JSON-formatted crash data and a minidump-formatted
// memory dump, respectively, for a run.
struct sl2_crash_paths {
    wchar_t crash_path[MAX_PATH + 1];
    wchar_t mem_dump_path[MAX_PATH + 1];
    wchar_t initial_dump_path[MAX_PATH + 1];
};


// Our version of the AFL coverage map.
struct sl2_arena {
    wchar_t id[SL2_HASH_LEN + 1];
    uint8_t map[FUZZ_ARENA_SIZE];
};

#endif
