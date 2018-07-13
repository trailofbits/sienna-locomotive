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

    // // This is basically just a check that the server is running
    // DWORD err = GetLastError();
    // if (err != ERROR_PIPE_BUSY) {
    //     dr_log(NULL, DR_LOG_ALL, ERROR, "Could not open pipe (%x)", err);
    //     dr_exit_process(1);
    // }

    // if (!WaitNamedPipe(FUZZ_SERVER_PATH, 5000)) {
    //     dr_log(NULL, DR_LOG_ALL, ERROR, "Could not connect, timeout");
    //     SL2_DR_DEBUG("Could not connect, timeout\n", err);
    //     dr_exit_process(1);
    // }

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
    WriteFile(client->pipe, &event, sizeof(BYTE), &txsize, NULL);

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

