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
    // We expected fewer bytes from the server than we received.
    LongRead,
    // We wrote more bytes to the server that it expected.
    LongWrite,
    // We tried to perform an action on the server without a run ID.
    MissingRunID,
    // We tried to request a run ID from the server while already having one.
    AlreadyHasRunID,
    // We tried to perform an action on the server without an arena ID.
    MissingArenaID,
};

// A structure representing an active connection between a
// DynamoRIO client and the SL2 server.
struct sl2_conn {
    HANDLE pipe;
    UUID run_id;
    bool has_run_id;
};

// Opens a new connection to the SL2 server.
// This function should be used in conjunction with either `sl2_conn_request_run_id`
// *or* `sl2_conn_assign_run_id`, depending on the client's needs.
__declspec(dllexport) SL2Response sl2_conn_open(sl2_conn *conn);

// Ends a session with the SL2 server, *without* closing the connection.
// This allows an `sl2_conn` to be reused across multiple runs.
__declspec(dllexport) SL2Response sl2_conn_end_session(sl2_conn *conn);

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

// Requests information about a run's crash from the SL2 server.
// Stores crash information within a `sl2_crash_paths` structure.
__declspec(dllexport) SL2Response sl2_conn_request_crash_paths(sl2_conn *conn, sl2_crash_paths *paths);

// Requests a coverage arena from the SL2 server.
// `arena` is a pointer to an allocated (but potentially uninitialized) `sl2_arena`.
__declspec(dllexport) SL2Response sl2_conn_request_arena(sl2_conn *conn, sl2_arena *arena);

// Registers a coverage arena with the SL2 server.
// `arena` is a pointer to an allocated `sl2_arena`.
__declspec(dllexport) SL2Response sl2_conn_register_arena(sl2_conn *conn, sl2_arena *arena);

#endif
