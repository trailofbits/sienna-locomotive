#ifndef SL2_SERVER_API
#define SL2_SERVER_API

#include "common/util.h"
#include "common/mutation.hpp"
#include "server.hpp"
#include <Rpc.h>

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
    // We sent a request to the server, and the server failed to fulfill it.
    ServerError,
    // We sent a request to the server, and got a bad/nonsensical response back.
    BadValue,
};

// A structure representing an active connection between a
// DynamoRIO client and the SL2 server.
struct sl2_conn {
    HANDLE pipe;
    UUID run_id;
    bool has_run_id;
};

// Represents the advice given to a fuzzer by the server, for coverage
// guided fuzzing.
struct sl2_mutation_advice {
    sl2_strategy_t strategy;
    uint32_t table_idx;
};

// Opens a new connection to the SL2 server.
// This function should be used in conjunction with either `sl2_conn_request_run_id`
// *or* `sl2_conn_assign_run_id`, depending on the client's needs.
SL2_EXPORT
SL2Response sl2_conn_open(sl2_conn *conn);

// Ends a session with the SL2 server, *without* closing the connection.
// This allows an `sl2_conn` to be reused across multiple runs.
SL2_EXPORT
SL2Response sl2_conn_end_session(sl2_conn *conn);

// Closes an active connection with the SL2 server.
// Clients *must not* exit before calling this.
SL2_EXPORT
SL2Response sl2_conn_close(sl2_conn *conn);

// Associates this connection with an extant run ID.
SL2_EXPORT
SL2Response sl2_conn_assign_run_id(sl2_conn *conn, UUID run_id);

// Registers a mutation with the SL2 server.
// `mutation` is a pointer to a `sl2_mutation` containing the mutation's state.
SL2_EXPORT
SL2Response sl2_conn_register_mutation(sl2_conn *conn, sl2_mutation *mutation);

// Requests a replay (of a previously mutated buffer) from the SL2 server.
// `mut_count` is the Nth mutation requested.
// `bufsize` is the size of the mutable buffer, in bytes.
// `buffer` is the mutable buffer. This function writes to `buffer`.
SL2_EXPORT
SL2Response sl2_conn_request_replay(sl2_conn *conn, uint32_t mut_count, size_t bufsize, void *buffer);

// Requests information about a run's crash from the SL2 server.
// Stores crash information within a `sl2_crash_paths` structure.
SL2_EXPORT
SL2Response sl2_conn_request_crash_paths(sl2_conn *conn, uint64_t pid, sl2_crash_paths *paths);

// Requests a coverage arena from the SL2 server.
// `arena` is a pointer to an allocated (but potentially uninitialized) `sl2_arena`.
SL2_EXPORT
SL2Response sl2_conn_request_arena(sl2_conn *conn, sl2_arena *arena);

// Registers a coverage arena with the SL2 server.
// `arena` is a pointer to an allocated `sl2_arena`.
SL2_EXPORT
SL2Response sl2_conn_register_arena(sl2_conn *conn, sl2_arena *arena);

// Pings the SL2 server.
// `ok` is a pointer to a `uint8_t` that the server's response will be placed in.
SL2_EXPORT
SL2Response sl2_conn_ping(sl2_conn *conn, uint8_t *ok);

// Registers a pid with the SL2 server.
// `pid` is a process ID.
// `tracing` indicates whether the `pid` belongs to a tracer process (true) or a fuzzer
// process (false).
SL2_EXPORT
SL2Response sl2_conn_register_pid(sl2_conn *conn, uint64_t pid, bool tracing);

// Requests advice about mutation strategies from the server, based on previous
// code coverage statistics.
SL2_EXPORT
SL2Response sl2_conn_advise_mutation(sl2_conn *conn, sl2_arena *arena, sl2_mutation_advice *advice);

// Requests information about code coverage so far
SL2_EXPORT
SL2Response sl2_conn_get_coverage(sl2_conn *conn, sl2_arena *arena, bool *bucketing, uint32_t *score, uint32_t *tries_remaining);

#endif
