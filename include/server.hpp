#ifndef SL2_SERVER_HPP
#define SL2_SERVER_HPP

// The path to the local named pipe, used by the server to communicate with clients.
#define FUZZ_SERVER_PATH (L"\\\\.\\pipe\\fuzz_server")

// The file (under the run directory) in which the name of the program is stored.
#define FUZZ_RUN_PROGRAM_TXT (L"program.txt")

// The file (under the run directory) in which the arguments to the program are stored.
#define FUZZ_RUN_ARGUMENTS_TXT (L"arguments.txt")

// The file (under the run directory) in which the program's execution trace is stored.
#define FUZZ_RUN_EXECUTION_TRC (L"execution.trc")

// The file (under the run directory) in which the program's memory dump is stored.
#define FUZZ_RUN_MEM_DMP (L"mem.dmp")

// The file (under the run directory) in which the program's crash state is stored.
#define FUZZ_RUN_EXECUTION_CSH (L"execution.csh")

// The file (under the run directory) in which the program's crash triage info is stored.
#define FUZZ_RUN_CRASH_JSON (L"crash.json")

// The format for files (under the run directory) containing replayable mutations.
#define FUZZ_RUN_FKT_FMT (L"%d.fkt")

enum Event {
    // Request a new run ID from the server.
    EVT_RUN_ID,             // 0
    // Request a mutation from the server.
    EVT_MUTATION,           // 1
    // Request a replay from the server.
    EVT_REPLAY,             // 2
    // Request information about a run from the server.
    EVT_RUN_INFO,           // 3
    // Tell the server to finalize a run.
    EVT_RUN_COMPLETE,       // 4
    // Request a pathname for storing crash information from the server.
    EVT_CRASH_PATH,         // 5
    // Tell the server to end its session with this client.
    EVT_SESSION_TEARDOWN,   // 6
    // Request a pathname for storing a memory dump from the server.
    EVT_MEM_DMP_PATH,       // 7
    // Use this as a default value when handling multiple events.
    EVT_INVALID = 255,
};

#endif
