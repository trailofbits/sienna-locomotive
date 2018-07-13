#ifndef SL2_SERVER_API
#define SL2_SERVER_API

#include "server.hpp"

// TODO(ww): macros for abstracting ReadFile/WriteFile.

enum class SL2Response {
    OK,
    BadPipe,
    ServerNotRunning,
    ShortRead,
    ShortWrite,
    MissingRunID,
    AlreadyHasRunID,
};

struct sl2_client {
    HANDLE pipe;
    UUID run_id;
    bool has_run_id;
};

struct sl2_run_info {
    wchar_t *program;
    wchar_t *arguments;
};

__declspec(dllexport) SL2Response sl2_client_open(sl2_client *client);
__declspec(dllexport) SL2Response sl2_client_close(sl2_client *client);

__declspec(dllexport) SL2Response sl2_client_request_run_id(sl2_client *client, wchar_t *target_name, wchar_t *target_args);
__declspec(dllexport) SL2Response sl2_client_assign_run_id(sl2_client *client, UUID run_id);

// TODO(ww): Allow the caller to request a particular mutation type?
__declspec(dllexport) SL2Response sl2_client_request_mutation(sl2_client *client, DWORD func_type, DWORD mut_count, wchar_t *filename, size_t position, size_t bufsize, void *buffer);
__declspec(dllexport) SL2Response sl2_client_request_replay(sl2_client *client, DWORD mutation_count, void *buf, size_t size);

__declspec(dllexport) SL2Response sl2_client_request_run_info(sl2_client *client, sl2_run_info *info);
__declspec(dllexport) SL2Response sl2_client_destroy_run_info(sl2_run_info *info);

__declspec(dllexport) SL2Response sl2_client_finalize_run(sl2_client *client, bool crash, bool preserve);
__declspec(dllexport) SL2Response sl2_client_request_crash_path(sl2_client *client, wchar_t **crash_path);

#endif
