#include <stdint.h>

#include <Windows.h>

#include "common/sl2_server_api.hpp"

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
    WriteFile(conn->pipe, &event, sizeof(event), &txsize, NULL);

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
    WriteFile(conn->pipe, &event, sizeof(event), &txsize, NULL);

    // Then, read the UUID from the server.
    ReadFile(conn->pipe, &run_id, sizeof(run_id), &txsize, NULL);

    // Finally, send the server our length-prefixed program name and arguments.
    DWORD len = lstrlen(target_name) * sizeof(wchar_t);
    WriteFile(conn->pipe, &len, sizeof(len), &txsize, NULL);
    WriteFile(conn->pipe, target_name, len, &txsize, NULL);

    len = lstrlen(target_args) * sizeof(wchar_t);
    WriteFile(conn->pipe, &len, sizeof(len), &txsize, NULL);
    WriteFile(conn->pipe, target_args, len, &txsize, NULL);

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

    // Then, send the length-prefixed filename associated with the mutation buffer.
    // NOTE(ww): If the filename is NULL (as it currently is for many of the functions
    // we mutate from), then we send only the length (0) to tell the server not
    // to expect a filename.
    DWORD len = lstrlen(filename) * sizeof(wchar_t);
    WriteFile(conn->pipe, &len, sizeof(len), &txsize, NULL);

    if (len > 0) {
        WriteFile(conn->pipe, filename, len, &txsize, NULL);
    }

    // Then, send the position within and total size of the incoming buffer.
    WriteFile(conn->pipe, &position, sizeof(position), &txsize, NULL);
    WriteFile(conn->pipe, &bufsize, sizeof(bufsize), &txsize, NULL);

    // Finally, both send the buffer and receive it, mutating it in place.
    WriteFile(conn->pipe, buffer, bufsize, &txsize, NULL);
    ReadFile(conn->pipe, buffer, bufsize, &txsize, NULL);

    // TODO(ww): error returns
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
    WriteFile(conn->pipe, &event, sizeof(event), &txsize, NULL);

    // Then, tell the server which run we're requesting the replay for.
    WriteFile(conn->pipe, &(conn->run_id), sizeof(conn->run_id), &txsize, NULL);

    // Then, tell the server which mutation we're expecting from that run.
    WriteFile(conn->pipe, &mut_count, sizeof(mut_count), &txsize, NULL);

    // Finally, tell the server how many bytes we expect to receive and
    // receive those bytes into the buffer.
    WriteFile(conn->pipe, &bufsize, sizeof(bufsize), &txsize, NULL);
    ReadFile(conn->pipe, buffer, bufsize, &txsize, NULL);

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
    WriteFile(conn->pipe, &event, sizeof(event), &txsize, NULL);

    // Then, tell the server which run we want information for.
    WriteFile(conn->pipe, &(conn->run_id), sizeof(conn->run_id), &txsize, NULL);

    // Then, read the length-prefixed program pathname and argument list.
    // NOTE(ww): The server sends us the length of the buffer, not the length of
    // the widechar string (which would be half of the buffer's size).
    DWORD len;

    ReadFile(conn->pipe, &len, sizeof(len), &txsize, NULL);
    info->program = (wchar_t *) malloc(len + 1);
    memset(info->program, 0, len + 1);

    ReadFile(conn->pipe, info->program, len, &txsize, NULL);

    ReadFile(conn->pipe, &len, sizeof(len), &txsize, NULL);
    info->arguments = (wchar_t *) malloc(len + 1);
    memset(info->arguments, 0, len + 1);

    ReadFile(conn->pipe, info->arguments, len, &txsize, NULL);

    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_conn_destroy_run_info(sl2_run_info *info)
{
    if (info->program) {
        free(info->program);
    }

    if (info->arguments) {
        free(info->arguments);
    }

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
    WriteFile(conn->pipe, &event, sizeof(event), &txsize, NULL);

    // Then, tell the server which run we're finalizing.
    WriteFile(conn->pipe, &(conn->run_id), sizeof(conn->run_id), &txsize, NULL);

    // Then, tell the server whether we've found a crash.
    WriteFile(conn->pipe, &crash, sizeof(crash), &txsize, NULL);

    // Finally, tell the server if we'd like to preserve the run's on-disk state,
    // even without a crash. This is only checked if by the server if crash is false.
    WriteFile(conn->pipe, &preserve, sizeof(preserve), &txsize, NULL);

    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_conn_request_crash_path(
    sl2_conn *conn,
    wchar_t **crash_path)
{
    BYTE event = EVT_CRASH_PATH;
    DWORD txsize;

    // If the connection doesn't have a run ID, then we don't know which crash path to
    // request.
    if (!conn->has_run_id) {
        return SL2Response::MissingRunID;
    }

    // First, tell the server that we're requesting a crash path.
    WriteFile(conn->pipe, &event, sizeof(event), &txsize, NULL);

    // Then, tell the server which run we want the crash path for.
    WriteFile(conn->pipe, &(conn->run_id), sizeof(conn->run_id), &txsize, NULL);

    // Finally, read the length-prefixed crash path from the server.
    // NOTE(ww): Like EVT_RUN_INFO, the lengths here are buffer lengths,
    // not string lengths.
    size_t len;

    ReadFile(conn->pipe, &len, sizeof(len), &txsize, NULL);
    *crash_path = (wchar_t *) malloc(len + 1);
    memset(*crash_path, 0, len + 1);

    ReadFile(conn->pipe, *crash_path, len, &txsize, NULL);

    return SL2Response::OK;
}

