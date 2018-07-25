#include <stdint.h>

#include <Windows.h>

#include "common/sl2_server_api.hpp"

// NOTE(ww): The macros below assume the following state:
// conn: an `sl2_conn *`
// txsize: a `DWORD`
#define SL2_CONN_WRITE(thing, size) (WriteFile(conn->pipe, thing, size, &txsize, NULL))
#define SL2_CONN_READ(thing, size) (ReadFile(conn->pipe, thing, size, &txsize, NULL))

#define SL2_CONN_EVT(event) do {       \
    uint8_t evt = event;                     \
    SL2_CONN_WRITE(&evt, sizeof(evt)); \
} while(0)

// Writes a length-prefixed wide string to the server.
static
void sl2_conn_write_prefixed_string(sl2_conn *conn, wchar_t *message)
{
    DWORD txsize;
    size_t len = lstrlen(message) * sizeof(wchar_t);

    SL2_CONN_WRITE(&len, sizeof(len));

    // If the string is empty, don't bother sending it.
    if (len > 0) {
        SL2_CONN_WRITE(message, len);
    }
}

// Reads a length-prefixed wide string from the server, up to `maxlen` wide chars.
// `maxlen` does *not* include the trailing NULL, so callers *must* ensure that
// `message` can hold at at least `(maxlen * sizeof(wchar_t)) + 1` bytes.
static
SL2Response sl2_conn_read_prefixed_string(sl2_conn *conn, wchar_t *message, size_t maxlen)
{
    DWORD txsize;
    size_t len;

    SL2_CONN_READ(&len, sizeof(len));

    if ((len / sizeof(wchar_t)) > maxlen) {
        return SL2Response::LongRead;
    }

    SL2_CONN_READ(message, len);
    message[len / sizeof(wchar_t)] = '\0';

    return SL2Response::OK;
}

__declspec(dllexport)
SL2Response sl2_conn_open(sl2_conn *conn)
{
    HANDLE pipe;

    pipe = CreateFile(FUZZ_SERVER_PATH, GENERIC_READ | GENERIC_WRITE,
                      0, NULL, OPEN_EXISTING, 0, NULL);

    if (pipe == INVALID_HANDLE_VALUE) {
        return SL2Response::BadPipe;
    }

    DWORD readMode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(pipe, &readMode, NULL, NULL);

    conn->pipe = pipe;

    // NOTE(ww): We zero the run_id out here so that using a connection
    // without requesting a run ID first will be a huge giveaway.
    conn->run_id = {0};
    conn->has_run_id = false;

    return SL2Response::OK;
}

__declspec(dllexport)
SL2Response sl2_conn_end_session(sl2_conn *conn)
{
    DWORD txsize;

    // Tell the server that we want to end our session.
    SL2_CONN_EVT(EVT_SESSION_TEARDOWN);

    conn->has_run_id = false;

    return SL2Response::OK;
}

__declspec(dllexport)
SL2Response sl2_conn_close(sl2_conn *conn)
{
    sl2_conn_end_session(conn);

    CloseHandle(conn->pipe);

    // TODO(ww): error returns
    return SL2Response::OK;
}

__declspec(dllexport)
SL2Response sl2_conn_request_run_id(sl2_conn *conn, wchar_t *target_name, wchar_t *target_args)
{
    UUID run_id;
    DWORD txsize;

    // First, tell the server that we're requesting a UUID.
    SL2_CONN_EVT(EVT_RUN_ID);

    // Then, read the UUID from the server.
    SL2_CONN_READ(&run_id, sizeof(run_id));

    sl2_conn_write_prefixed_string(conn, target_name);
    sl2_conn_write_prefixed_string(conn, target_args);

    conn->run_id = run_id;
    conn->has_run_id = true;

    return SL2Response::OK;
}

__declspec(dllexport)
SL2Response sl2_conn_assign_run_id(sl2_conn *conn, UUID run_id)
{
    if (conn->has_run_id) {
        return SL2Response::AlreadyHasRunID;
    }

    conn->run_id = run_id;
    conn->has_run_id = true;

    return SL2Response::OK;
}

__declspec(dllexport)
SL2Response sl2_conn_register_mutation(sl2_conn *conn, sl2_mutation *mutation)
{
    DWORD txsize;

    if (!conn->has_run_id) {
        return SL2Response::MissingRunID;
    }

    // First, tell the server that we're registering a mutation.
    SL2_CONN_EVT(EVT_REGISTER_MUTATION);

    // Then, tell the server which run the mutation is associated with.
    SL2_CONN_WRITE(&(conn->run_id), sizeof(conn->run_id));

    // Then, send our mutation state over.
    // TODO(ww): Check for truncated writes.
    SL2_CONN_WRITE(&(mutation->function), sizeof(mutation->function));
    SL2_CONN_WRITE(&(mutation->mut_count), sizeof(mutation->mut_count));
    sl2_conn_write_prefixed_string(conn, mutation->resource);
    SL2_CONN_WRITE(&(mutation->position), sizeof(mutation->position));
    SL2_CONN_WRITE(&(mutation->bufsize), sizeof(mutation->bufsize));
    SL2_CONN_WRITE(mutation->buffer, mutation->bufsize);

    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_conn_request_replay(
    sl2_conn *conn,
    uint32_t mut_count,
    size_t bufsize,
    void *buffer)
{
    DWORD txsize;

    // If the connection doesn't have a run ID, then we don't know which
    // replay to request.
    if (!conn->has_run_id) {
        return SL2Response::MissingRunID;
    }

    // First, tell the server that we're requesting a replay.
    SL2_CONN_EVT(EVT_REPLAY);

    // Then, tell the server which run we're requesting the replay for.
    SL2_CONN_WRITE(&(conn->run_id), sizeof(conn->run_id));

    // Then, tell the server which mutation we're expecting from that run.
    SL2_CONN_WRITE(&mut_count, sizeof(mut_count));

    // Finally, tell the server how many bytes we expect to receive and
    // receive those bytes into the buffer.
    SL2_CONN_WRITE(&bufsize, sizeof(bufsize));
    SL2_CONN_READ(buffer, bufsize);

    return SL2Response::OK;
}

__declspec(dllexport)
SL2Response sl2_conn_finalize_run(sl2_conn *conn, bool crash, bool preserve)
{
    DWORD txsize;

    // If the connection doesn't a run ID, then we don't have a run to finalize.
    if (!conn->has_run_id) {
        return SL2Response::MissingRunID;
    }

    // First, tell the server that we're finalizing a run.
    SL2_CONN_EVT(EVT_RUN_COMPLETE);

    // Then, tell the server which run we're finalizing.
    SL2_CONN_WRITE(&(conn->run_id), sizeof(conn->run_id));

    // Then, tell the server whether we've found a crash.
    SL2_CONN_WRITE(&crash, sizeof(crash));

    // Finally, tell the server if we'd like to preserve the run's on-disk state,
    // even without a crash. This is only checked if by the server if crash is false.
    SL2_CONN_WRITE(&preserve, sizeof(preserve));

    return SL2Response::OK;
}

__declspec(dllexport)
SL2Response sl2_conn_request_crash_paths(sl2_conn *conn, sl2_crash_paths *paths)
{
    DWORD txsize;

    // If the connection doesn't a run ID, then we don't have a run to finalize.
    if (!conn->has_run_id) {
        return SL2Response::MissingRunID;
    }

    // First, tell the server that we'd like the crash paths for a run.
    SL2_CONN_EVT(EVT_CRASH_PATHS);

    // Then, tell the server which run we're requesting crash paths for.
    SL2_CONN_WRITE(&(conn->run_id), sizeof(conn->run_id));

    // Finally, read the actual crash paths from the server.
    sl2_conn_read_prefixed_string(conn, paths->crash_path, MAX_PATH);
    sl2_conn_read_prefixed_string(conn, paths->mem_dump_path, MAX_PATH);
    sl2_conn_read_prefixed_string(conn, paths->initial_dump_path, MAX_PATH);

    return SL2Response::OK;
}

__declspec(dllexport)
SL2Response sl2_conn_request_arena(sl2_conn *conn, sl2_arena *arena)
{
    DWORD txsize;

    if (!arena->id) {
        return SL2Response::MissingArenaID;
    }

    // First, tell the server that we'd like a coverage arena.
    SL2_CONN_EVT(EVT_GET_ARENA);

    // Then, tell the server which coverage arena we'd like.
    // NOTE(ww): This identifier is a hash of targetting information known to
    // every instance of the fuzzer, meaning that each run on the same target application
    // and function(s) should produce the same identifier.
    sl2_conn_write_prefixed_string(conn, arena->id);

    // Finally, read the arena from the server.
    SL2_CONN_READ(arena->map, FUZZ_ARENA_SIZE);

    return SL2Response::OK;
}

__declspec(dllexport)
SL2Response sl2_conn_register_arena(sl2_conn *conn, sl2_arena *arena)
{
    DWORD txsize;

    if (!arena->id) {
        return SL2Response::MissingArenaID;
    }

    // First, tell the server that we're sending it a coverage arena.
    SL2_CONN_EVT(EVT_SET_ARENA);

    // Then, tell the server which ID the arena is associated with.
    sl2_conn_write_prefixed_string(conn, arena->id);

    // Finally, write the arena data to the server.
    SL2_CONN_WRITE(arena->map, FUZZ_ARENA_SIZE);

    return SL2Response::OK;
}


