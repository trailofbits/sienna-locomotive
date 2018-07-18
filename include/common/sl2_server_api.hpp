#ifndef SL2_SERVER_API
#define SL2_SERVER_API

#include "server.hpp"

// An enum of response codes used by the calls below to indicate
// their success or failure.
enum class SL2Response {
    // Nothing went wrong.
    OK,
    // The pipe used to talk to the server is invalid or closed.
    BadPipe,
    // We expected a valid path from the server, but were given something too long.
    MaxPath,
    // The server is not running, or not accepting connections.
    ServerNotRunning,
    // We expected more bytes from the server than we received.
    ShortRead,
    // We wrote fewer bytes to the server than we expected.
    ShortWrite,
    // We tried to perform an action on the server without a run ID.
    MissingRunID,
    // We tried to request a run ID from the server while already having one.
    AlreadyHasRunID,
};

// A structure representing an active connection between a
// DynamoRIO client and the SL2 server.
struct sl2_conn {
    HANDLE pipe;
    UUID run_id;
    bool has_run_id;
};

// Represents the state associated with a mutation, including
// the function whose input has been mutated, the mutation count,
// the resource behind the mutation, the position within the resource,
// the size of the mutated buffer, and the mutated buffer itself.
//
// May represent the state *before* a mutation, meaning that `buffer` has not
// changed yet.
struct sl2_mutation {
    DWORD function;
    DWORD mut_count;
    wchar_t *resource;
    size_t position;
    size_t bufsize;
    unsigned char *buffer;
};

// A structure containing valid pathnames for storage
// of JSON-formatted crash data and a minidump-formatted
// memory dump, respectively, for a run.
struct sl2_crash_paths {
    wchar_t crash_path[MAX_PATH + 1];
    wchar_t dump_path[MAX_PATH + 1];
};

// Opens a new connection to the SL2 server.
// This function should be used in conjunction with either `sl2_conn_request_run_id`
// *or* `sl2_conn_assign_run_id`, depending on the client's needs.
__declspec(dllexport) SL2Response sl2_conn_open(sl2_conn *conn);

// Closes an active connection with the SL2 server.
// Clients *must not* exit before calling this.
__declspec(dllexport) SL2Response sl2_conn_close(sl2_conn *conn);

// Requests a new run ID from the SL2 server.
// `target_name` and `target_args` contain the program name and arguments that
// the server should associate with the run ID.
__declspec(dllexport) SL2Response sl2_conn_request_run_id(sl2_conn *conn, wchar_t *target_name, wchar_t *target_args);

// Associates this connection with an extant run ID.
__declspec(dllexport) SL2Response sl2_conn_assign_run_id(sl2_conn *conn, UUID run_id);

// Registers a mutation with the SL2 server.
// `mutation` is a pointer to a `sl2_mutation` containing the mutation's state.
__declspec(dllexport) SL2Response sl2_conn_register_mutation(sl2_conn *conn, sl2_mutation *mutation);

// Requests a replay (of a previously mutated buffer) from the SL2 server.
// `mut_count` is the Nth mutation requested.
// `bufsize` is the size of the mutable buffer, in bytes.
// `buffer` is the mutable buffer. This function writes to `buffer`.
__declspec(dllexport) SL2Response sl2_conn_request_replay(sl2_conn *conn, DWORD mut_count, size_t bufsize, void *buffer);

// Finalizes a run with the SL2 server.
// `crash` indicates whether the run crashed or not.
// `preserve` indicates whether to keep the run on disk, even without a crash.
__declspec(dllexport) SL2Response sl2_conn_finalize_run(sl2_conn *conn, bool crash, bool preserve);

// Requests a path for storing crash information for a run from the SL2 server.
// `crash_path` is a buffer capable of storing MAX_PATH wide characters, plus a null terminator.
__declspec(dllexport) SL2Response sl2_conn_request_crash_path(sl2_conn *conn, wchar_t *crash_path);

// Requests a path for storing a minidump for a run from the SL2 server.
// `dump_path` is a buffer capable of storing MAX_PATH wide characters, plus a null terminator.
__declspec(dllexport) SL2Response sl2_conn_request_minidump_path(sl2_conn *conn, wchar_t *dump_path);

// Requests information about a run's crash from the SL2 server.
// Stores crash information within a `sl2_crash_paths` structure.
// NOTE(ww): This should be preferred over calling `sl2_conn_request_crash_path` and
// `sl2_conn_request_minidump_path` individually.
__declspec(dllexport) SL2Response sl2_conn_request_crash_paths(sl2_conn *conn, sl2_crash_paths *paths);

#endif
