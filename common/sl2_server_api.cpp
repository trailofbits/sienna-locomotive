#include <stdint.h>

#include <Windows.h>

#include "common/sl2_server_api.hpp"

__declspec(dllexport) SL2Response sl2_client_open(sl2_client *client)
{
    HANDLE pipe;

    pipe = CreateFile(FUZZ_SERVER_PATH, GENERIC_READ | GENERIC_WRITE,
                      0, NULL, OPEN_EXISTING, 0, NULL);

    if (pipe == INVALID_HANDLE_VALUE) {
        return SL2Response::BadPipe;
    }

    DWORD readMode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(pipe, &readMode, NULL, NULL);

    client->pipe = pipe;

    // NOTE(ww): We zero the run_id out here so that using a client without requesting
    // a run ID first will be a huge giveaway.
    client->run_id = {0};
    client->has_run_id = false;

    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_client_close(sl2_client *client)
{
    BYTE event = EVT_SESSION_TEARDOWN;
    DWORD txsize;

    // Tell the server that we want to end our session.
    WriteFile(client->pipe, &event, sizeof(event), &txsize, NULL);

    CloseHandle(client->pipe);

    // TODO(ww): error returns
    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_client_request_run_id(
    sl2_client *client,
    wchar_t *target_name,
    wchar_t *target_args)
{
    UUID run_id;
    BYTE event = EVT_RUN_ID;
    DWORD txsize;

    // First, tell the server that we're requesting a UUID.
    WriteFile(client->pipe, &event, sizeof(event), &txsize, NULL);

    // Then, read the UUID from the server.
    ReadFile(client->pipe, &run_id, sizeof(run_id), &txsize, NULL);

    // Finally, send the server our length-prefixed program name and arguments.
    DWORD len = lstrlen(target_name) * sizeof(wchar_t);
    WriteFile(client->pipe, &len, sizeof(len), &txsize, NULL);
    WriteFile(client->pipe, target_name, len, &txsize, NULL);

    len = lstrlen(target_args) * sizeof(wchar_t);
    WriteFile(client->pipe, &len, sizeof(len), &txsize, NULL);
    WriteFile(client->pipe, target_args, len, &txsize, NULL);

    client->run_id = run_id;
    client->has_run_id = true;

    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_client_assign_run_id(sl2_client *client, UUID run_id)
{
    if (client->has_run_id) {
        return SL2Response::AlreadyHasRunID;
    }

    client->run_id = run_id;
    client->has_run_id = true;

    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_client_request_mutation(
    sl2_client *client,
    DWORD func_type,
    DWORD mut_count,
    wchar_t *filename,
    size_t position,
    size_t bufsize,
    void *buffer)
{
    BYTE event = EVT_MUTATION;
    DWORD txsize;

    // If the client doesn't have a run ID, then we don't have any state
    // to request a mutation against.
    if (!client->has_run_id) {
        return SL2Response::MissingRunID;
    }

    // First, tell the server that we're requesting a mutation.
    WriteFile(client->pipe, &event, sizeof(event), &txsize, NULL);

    // Then, give the server our run ID.
    WriteFile(client->pipe, &(client->run_id), sizeof(client->run_id), &txsize, NULL);

    // Then, tell the server the fuction type receiving the mutation.
    // NOTE(ww): The server doesn't currently use this information, other
    // than dumping it to the FTK. See sl2_dr_client.hpp for the mapping
    // of these numbers to function names.
    WriteFile(client->pipe, &func_type, sizeof(func_type), &txsize, NULL);

    // Then, tell the server the current mutation count.
    // NOTE(ww): The server uses this to construct the FTK's path,
    // e.g., "...\0.ftk". But with the current implementation, this number
    // is always 0, so it might be worth just removing.
    WriteFile(client->pipe, &mut_count, sizeof(mut_count), &txsize, NULL);

    // Then, send the length-prefixed filename associated with the mutation buffer.
    // NOTE(ww): If the filename is NULL (as it currently is for many of the functions
    // we mutate from), then we send only the length (0) to tell the server not
    // to expect a filename.
    DWORD len = lstrlen(filename) * sizeof(wchar_t);
    WriteFile(client->pipe, &len, sizeof(len), &txsize, NULL);

    if (len > 0) {
        WriteFile(client->pipe, filename, len, &txsize, NULL);
    }

    // Then, send the position within and total size of the incoming buffer.
    WriteFile(client->pipe, &position, sizeof(position), &txsize, NULL);
    WriteFile(client->pipe, &bufsize, sizeof(bufsize), &txsize, NULL);

    // Finally, both send the buffer and receive it, mutating it in place.
    WriteFile(client->pipe, buffer, bufsize, &txsize, NULL);
    ReadFile(client->pipe, buffer, bufsize, &txsize, NULL);

    // TODO(ww): error returns
    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_client_request_replay(
    sl2_client *client,
    DWORD mut_count,
    size_t bufsize,
    void *buffer)
{
    BYTE event = EVT_REPLAY;
    DWORD txsize;

    // If the client doesn't have a run ID, then we don't know which
    // replay to request.
    if (!client->has_run_id) {
        return SL2Response::MissingRunID;
    }

    // First, tell the server that we're requesting a replay.
    WriteFile(client->pipe, &event, sizeof(event), &txsize, NULL);

    // Then, tell the server which run we're requesting the replay for.
    WriteFile(client->pipe, &(client->run_id), sizeof(client->run_id), &txsize, NULL);

    // Then, tell the server which mutation we're expecting from that run.
    WriteFile(client->pipe, &mut_count, sizeof(mut_count), &txsize, NULL);

    // Finally, tell the server how many bytes we expect to receive and
    // receive those bytes into the buffer.
    WriteFile(client->pipe, &bufsize, sizeof(bufsize), &txsize, NULL);
    ReadFile(client->pipe, buffer, bufsize, &txsize, NULL);

    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_client_request_run_info(
    sl2_client *client,
    sl2_run_info *info)
{
    BYTE event = EVT_RUN_INFO;
    DWORD txsize;

    if (!client->has_run_id) {
        return SL2Response::MissingRunID;
    }

    // First, tell the server that we're requesting information about a run.
    WriteFile(client->pipe, &event, sizeof(event), &txsize, NULL);

    // Then, tell the server which run we want information for.
    WriteFile(client->pipe, &(client->run_id), sizeof(client->run_id), &txsize, NULL);

    // Then, read the length-prefixed program pathname and argument list.
    // NOTE(ww): The server sends us the length of the buffer, not the length of
    // the widechar string (which would be half of the buffer's size).
    DWORD len;

    ReadFile(client->pipe, &len, sizeof(len), &txsize, NULL);
    info->program = (wchar_t *) malloc(len + 1);
    memset(info->program, 0, len + 1);

    ReadFile(client->pipe, info->program, len, &txsize, NULL);

    ReadFile(client->pipe, &len, sizeof(len), &txsize, NULL);
    info->arguments = (wchar_t *) malloc(len + 1);
    memset(info->arguments, 0, len + 1);

    ReadFile(client->pipe, info->arguments, len, &txsize, NULL);

    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_client_destroy_run_info(sl2_run_info *info)
{
    if (info->program) {
        free(info->program);
    }

    if (info->arguments) {
        free(info->arguments);
    }

    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_client_finalize_run(
    sl2_client *client,
    bool crash,
    bool preserve)
{
    BYTE event = EVT_RUN_COMPLETE;
    DWORD txsize;

    // If the client doesn't a run ID, then we don't have a run to finalize.
    if (!client->has_run_id) {
        return SL2Response::MissingRunID;
    }

    // First, tell the server that we're finalizing a run.
    WriteFile(client->pipe, &event, sizeof(event), &txsize, NULL);

    // Then, tell the server which run we're finalizing.
    WriteFile(client->pipe, &(client->run_id), sizeof(client->run_id), &txsize, NULL);

    // Then, tell the server whether we've found a crash.
    WriteFile(client->pipe, &crash, sizeof(crash), &txsize, NULL);

    // Finally, tell the server if we'd like to preserve the run's on-disk state,
    // even without a crash. This is only checked if by the server if crash is false.
    WriteFile(client->pipe, &preserve, sizeof(preserve), &txsize, NULL);

    return SL2Response::OK;
}

__declspec(dllexport) SL2Response sl2_client_request_crash_path(
    sl2_client *client,
    wchar_t **crash_path)
{
    BYTE event = EVT_CRASH_PATH;
    DWORD txsize;

    // If the client doesn't have a run ID, then we don't know which crash path to
    // request.
    if (!client->has_run_id) {
        return SL2Response::MissingRunID;
    }

    // First, tell the server that we're requesting a crash path.
    WriteFile(client->pipe, &event, sizeof(event), &txsize, NULL);

    // Then, tell the server which run we want the crash path for.
    WriteFile(client->pipe, &(client->run_id), sizeof(client->run_id), &txsize, NULL);

    // Finally, read the length-prefixed crash path from the server.
    // NOTE(ww): Like EVT_RUN_INFO, the lengths here are buffer lengths,
    // not string lengths.
    size_t len;

    ReadFile(client->pipe, &len, sizeof(len), &txsize, NULL);
    *crash_path = (wchar_t *) malloc(len + 1);
    memset(*crash_path, 0, len + 1);

    ReadFile(client->pipe, *crash_path, len, &txsize, NULL);

    return SL2Response::OK;
}

