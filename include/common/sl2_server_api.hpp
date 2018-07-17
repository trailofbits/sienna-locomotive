#ifndef SL2_SERVER_API
#define SL2_SERVER_API

#include "server.hpp"

// TODO(ww): macros for abstracting ReadFile/WriteFile.

// An enum of response codes used by the calls below to indicate
// their success or failure.
enum class SL2Response {
    // Nothing went wrong.
    OK,
    // The pipe used to talk to the server is invalid or closed.
    BadPipe,
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

// A structure containing the executable name and arguments of a
// targeted application. See `sl2_conn_request_run_info` for
// populating this structure and `sl2_conn_destroy_run_info`
// for destroying it.
struct sl2_run_info {
    wchar_t *program;
    wchar_t *arguments;
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

// Requests a mutation from the SL2 server.
// `func_type` corresponds to one of the Function enums in sl2_dr_client.hpp.
// `mut_count` is the Nth mutation requested.
// `filename` contains the fully qualified path to the file whose buffer is being mutated.
// NOTE(ww): In the current implementation, `filename` can be NULL.
// `position` is the offset within `filename` that the buffer begins at.
// NOTE(ww): In the current implementation, `position` isn't used (but is recorded in the FKT).
// `bufsize` is the size of the mutable buffer, in bytes.
// `buffer` is the mutable buffer. This function both reads from and writes to `buffer`.
// TODO(ww): Allow the caller to request a particular mutation type?
__declspec(dllexport) SL2Response sl2_conn_request_mutation(sl2_conn *conn, DWORD func_type, DWORD mut_count, wchar_t *filename, size_t position, size_t bufsize, void *buffer);

// Requests a replay (of a previously mutated buffer) from the SL2 server.
// `mut_count` is the Nth mutation requested.
// `bufsize` is the size of the mutable buffer, in bytes.
// `buffer` is the mutable buffer. This function writes to `buffer`.
__declspec(dllexport) SL2Response sl2_conn_request_replay(sl2_conn *conn, DWORD mut_count, size_t bufsize, void *buffer);

// Requests information about a run from the SL2 server.
// Stores run information within a `sl2_run_info` structure.
// The `sl2_run_info` structure passed to this function should be freed using
// `sl2_conn_destroy_run_info` when no longer needed.
__declspec(dllexport) SL2Response sl2_conn_request_run_info(sl2_conn *conn, sl2_run_info *info);

// Destroys the given `sl2_run_info`.
__declspec(dllexport) SL2Response sl2_conn_destroy_run_info(sl2_run_info *info);

// Finalizes a run with the SL2 server.
// `crash` indicates whether the run crashed or not.
// `preserve` indicates whether to keep the run on disk, even without a crash.
__declspec(dllexport) SL2Response sl2_conn_finalize_run(sl2_conn *conn, bool crash, bool preserve);

// Requests a path for storing crash information for a run from the SL2 server.
// `crash_path` is a pointer to a wide C string, which gets allocated internally.
// Clients should `free` `crash_path` when no longer needed.
__declspec(dllexport) SL2Response sl2_conn_request_crash_path(sl2_conn *conn, wchar_t **crash_path);

// Requests a path for storing a minidump for a run from the SL2 server.
// `dump_path` is a pointer to a wide C string, which gets allocated internally.
// Clients should `free` `dump_path` when no longer needed.
__declspec(dllexport) SL2Response sl2_conn_request_minidump_path(sl2_conn *conn, wchar_t **dump_path);

#endif
