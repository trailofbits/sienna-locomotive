#ifndef SL2_SERVER_HPP
#define SL2_SERVER_HPP

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

// TODO: check then delete all the tracing stuff
enum Event {
    EVT_RUN_ID,             // 0
    EVT_MUTATION,           // 1
    EVT_REPLAY,             // 2
    EVT_RUN_INFO,           // 3
    EVT_RUN_COMPLETE,       // 4
    EVT_CRASH_PATH,         // 5
};

#endif
