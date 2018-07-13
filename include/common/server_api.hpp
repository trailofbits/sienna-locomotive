#ifndef SL2_SERVER_API
#define SL2_SERVER_API

#include "server.hpp"

struct sl2_client {
    HANDLE pipe;
    UUID run_id;
};

struct sl2_run_info {
    wchar_t *program;
    wchar_t *arguments;
};

bool sl2_server_open(sl2_client *client);

// TODO(ww): Allow the caller to request a particular mutation type?
int sl2_client_request_mutation(sl2_client *client, wchar_t *filename, size_t position, void *buf, size_t size);
int sl2_client_request_replay(sl2_client *client, int mutation_count, void *buf, size_t size);

int sl2_client_request_run_info(sl2_client *client, sl2_run_info *info);
int sl2_client_destroy_run_unfo(sl2_run_info *info);

int sl2_client_finalize_run(sl2_client *client, bool crash, bool remove);
int sl2_client_request_crash_path(sl2_client *client, wchar_t **crash_path);

#endif
