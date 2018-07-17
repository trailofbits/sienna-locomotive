#include <stdint.h>

#include <Windows.h>

#include "common/sl2_server_api.hpp"

#define SL2_CONN_WRITE(conn, thing, size) (WriteFile(conn->pipe, thing, size, &txsize, NULL))
#define SL2_CONN_READ(conn, thing, size) (ReadFile(conn->pipe, thing, size, &txsize, NULL))

static void sl2_conn_write_prefixed_string(sl2_conn *conn, wchar_t *message)
{
    DWORD txsize;
    size_t len = lstrlen(message) * sizeof(wchar_t);

    SL2_CONN_WRITE(conn, &len, sizeof(len));

    // If the string is empty, don't bother sending it.
    if (len > 0) {
        SL2_CONN_WRITE(conn, message, len);
    }
}

__declspec(dllexport) SL2Response sl2_conn_open(sl2_conn *conn)
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

__declspec(dllexport) SL2Response sl2_conn_close(sl2_conn *conn)
{
    BYTE event = EVT_SESSION_TEARDOWN;
    DWORD txsize;

    // Tell the server that we want to end our session.
    SL2_CONN_WRITE(conn, &event, sizeof(event));

    CloseHandle(conn->pipe);

    // TODO(ww): error returns
    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_conn_request_run_id(
    sl2_conn *conn,
    wchar_t *target_name,
    wchar_t *target_args)
{
    UUID run_id;
    BYTE event = EVT_RUN_ID;
    DWORD txsize;

    // First, tell the server that we're requesting a UUID.
    SL2_CONN_WRITE(conn, &event, sizeof(event));

    // Then, read the UUID from the server.
    SL2_CONN_READ(conn, &run_id, sizeof(run_id));

    sl2_conn_write_prefixed_string(conn, target_name);
    sl2_conn_write_prefixed_string(conn, target_args);

    conn->run_id = run_id;
    conn->has_run_id = true;

    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_conn_assign_run_id(sl2_conn *conn, UUID run_id)
{
    if (conn->has_run_id) {
        return SL2Response::AlreadyHasRunID;
    }

    conn->run_id = run_id;
    conn->has_run_id = true;

    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_conn_request_mutation(
    sl2_conn *conn,
    DWORD func_type,
    DWORD mut_count,
    wchar_t *filename,
    size_t position,
    size_t bufsize,
    void *buffer)
{
    BYTE event = EVT_MUTATION;
    DWORD txsize;

    // If the connection doesn't have a run ID, then we don't have any state
    // to request a mutation against.
    if (!conn->has_run_id) {
        return SL2Response::MissingRunID;
    }

    // First, tell the server that we're requesting a mutation.
    WriteFile(conn->pipe, &event, sizeof(event), &txsize, NULL);

    // Then, give the server our run ID.
    WriteFile(conn->pipe, &(conn->run_id), sizeof(conn->run_id), &txsize, NULL);

    // Then, tell the server the fuction type receiving the mutation.
    // NOTE(ww): The server doesn't currently use this information, other
    // than dumping it to the FTK. See sl2_dr_client.hpp for the mapping
    // of these numbers to function names.
    WriteFile(conn->pipe, &func_type, sizeof(func_type), &txsize, NULL);

    // Then, tell the server the current mutation count.
    // NOTE(ww): The server uses this to construct the FTK's path,
    // e.g., "...\0.ftk". But with the current implementation, this number
    // is always 0, so it might be worth just removing.
    WriteFile(conn->pipe, &mut_count, sizeof(mut_count), &txsize, NULL);

    sl2_conn_write_prefixed_string(conn, filename);

    // Then, send the position within and total size of the incoming buffer.
    WriteFile(conn->pipe, &position, sizeof(position), &txsize, NULL);
    WriteFile(conn->pipe, &bufsize, sizeof(bufsize), &txsize, NULL);

    // Finally, both send the buffer and receive it, mutating it in place.
    WriteFile(conn->pipe, buffer, bufsize, &txsize, NULL);
    ReadFile(conn->pipe, buffer, bufsize, &txsize, NULL);

    // TODO(ww): error returns
    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_conn_register_mutation(
    sl2_conn *conn,
    sl2_mutation *mutation)
{
    BYTE event = EVT_REGISTER_MUTATION;
    DWORD txsize;

    if (!conn->has_run_id) {
        return SL2Response::MissingRunID;
    }

    // First, tell the server that we're registering a mutation.
    SL2_CONN_WRITE(conn, &event, sizeof(event));

    // Then, tell the server which run the mutation is associated with.
    SL2_CONN_WRITE(conn, &(conn->run_id), sizeof(conn->run_id));

    // Then, send our mutation state over.
    // TODO(ww): Check for truncated writes.
    SL2_CONN_WRITE(conn, &(mutation->function), sizeof(mutation->function));
    SL2_CONN_WRITE(conn, &(mutation->mut_count), sizeof(mutation->mut_count));
    sl2_conn_write_prefixed_string(conn, mutation->resource);
    SL2_CONN_WRITE(conn, &(mutation->position), sizeof(mutation->position));
    SL2_CONN_WRITE(conn, &(mutation->bufsize), sizeof(mutation->bufsize));
    SL2_CONN_WRITE(conn, mutation->buffer, mutation->bufsize);

    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_conn_request_replay(
    sl2_conn *conn,
    DWORD mut_count,
    size_t bufsize,
    void *buffer)
{
    BYTE event = EVT_REPLAY;
    DWORD txsize;

    // If the connection doesn't have a run ID, then we don't know which
    // replay to request.
    if (!conn->has_run_id) {
        return SL2Response::MissingRunID;
    }

    // First, tell the server that we're requesting a replay.
    SL2_CONN_WRITE(conn, &event, sizeof(event));

    // Then, tell the server which run we're requesting the replay for.
    SL2_CONN_WRITE(conn, &(conn->run_id), sizeof(conn->run_id));

    // Then, tell the server which mutation we're expecting from that run.
    SL2_CONN_WRITE(conn, &mut_count, sizeof(mut_count));

    // Finally, tell the server how many bytes we expect to receive and
    // receive those bytes into the buffer.
    SL2_CONN_WRITE(conn, &bufsize, sizeof(bufsize));
    SL2_CONN_READ(conn, buffer, bufsize);

    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_conn_request_run_info(
    sl2_conn *conn,
    sl2_run_info *info)
{
    BYTE event = EVT_RUN_INFO;
    DWORD txsize;

    if (!conn->has_run_id) {
        return SL2Response::MissingRunID;
    }

    // First, tell the server that we're requesting information about a run.
    SL2_CONN_WRITE(conn, &event, sizeof(event));

    // Then, tell the server which run we want information for.
    SL2_CONN_WRITE(conn, &(conn->run_id), sizeof(conn->run_id));

    // Then, read the length-prefixed program pathname and argument list.
    // NOTE(ww): The server sends us the length of the buffer, not the length of
    // the widechar string (which would be half of the buffer's size).
    size_t len;

    SL2_CONN_READ(conn, &len, sizeof(len));

    if (len > MAX_PATH) {
        return SL2Response::MaxPath;
    }

    memset(info->program, 0, len + 1);
    SL2_CONN_READ(conn, info->program, len);

    SL2_CONN_READ(conn, &len, sizeof(len));

    if (len > MAX_PATH) {
        return SL2Response::MaxPath;
    }

    memset(info->arguments, 0, len + 1);
    SL2_CONN_READ(conn, info->arguments, len);

    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_conn_finalize_run(
    sl2_conn *conn,
    bool crash,
    bool preserve)
{
    BYTE event = EVT_RUN_COMPLETE;
    DWORD txsize;

    // If the connection doesn't a run ID, then we don't have a run to finalize.
    if (!conn->has_run_id) {
        return SL2Response::MissingRunID;
    }

    // First, tell the server that we're finalizing a run.
    SL2_CONN_WRITE(conn, &event, sizeof(event));

    // Then, tell the server which run we're finalizing.
    SL2_CONN_WRITE(conn, &(conn->run_id), sizeof(conn->run_id));

    // Then, tell the server whether we've found a crash.
    SL2_CONN_WRITE(conn, &crash, sizeof(crash));

    // Finally, tell the server if we'd like to preserve the run's on-disk state,
    // even without a crash. This is only checked if by the server if crash is false.
    SL2_CONN_WRITE(conn, &preserve, sizeof(preserve));

    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_conn_request_crash_path(
    sl2_conn *conn,
    wchar_t *crash_path)
{
    BYTE event = EVT_CRASH_PATH;
    DWORD txsize;

    // If the connection doesn't have a run ID, then we don't know which crash path to
    // request.
    if (!conn->has_run_id) {
        return SL2Response::MissingRunID;
    }

    // First, tell the server that we're requesting a crash path.
    SL2_CONN_WRITE(conn, &event, sizeof(event));

    // Then, tell the server which run we want the crash path for.
    SL2_CONN_WRITE(conn, &(conn->run_id), sizeof(conn->run_id));

    // Finally, read the length-prefixed crash path from the server.
    // NOTE(ww): Like EVT_RUN_INFO, the lengths here are buffer lengths,
    // not string lengths.
    size_t len;

    SL2_CONN_READ(conn, &len, sizeof(len));

    if (len > MAX_PATH) {
        return SL2Response::MaxPath;
    }

    memset(crash_path, 0, len + 1);
    SL2_CONN_READ(conn, crash_path, len);

    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_conn_request_minidump_path(
    sl2_conn *conn,
    wchar_t *dump_path)
{
    BYTE event = EVT_MEM_DMP_PATH;
    DWORD txsize;

    // If the connection doesn't have a run ID, then we don't know which dump path to
    // request.
    if (!conn->has_run_id) {
        return SL2Response::MissingRunID;
    }

    // First, tell the server that we're requesting a dump path.
    SL2_CONN_WRITE(conn, &event, sizeof(event));

    // Then, tell the server which run we want the dump path for.
    SL2_CONN_WRITE(conn, &(conn->run_id), sizeof(conn->run_id));

    // Finally, read the length-prefixed dump path from the server.
    // NOTE(ww): Like EVT_RUN_INFO, the lengths here are buffer lengths,
    // not string lengths.
    size_t len;

    SL2_CONN_READ(conn, &len, sizeof(len));

    if (len > MAX_PATH) {
        return SL2Response::MaxPath;
    }

    memset(dump_path, 0, len + 1);
    SL2_CONN_READ(conn, dump_path, len);

    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_conn_request_crash_paths(
    sl2_conn *conn,
    sl2_crash_paths *paths)
{
    SL2Response resp;

    if ((resp = sl2_conn_request_crash_path(conn, paths->crash_path)) != SL2Response::OK) {
        return resp;
    }

    if ((resp = sl2_conn_request_minidump_path(conn, paths->dump_path)) != SL2Response::OK) {
        return resp;
    }

    return SL2Response::OK;
}
