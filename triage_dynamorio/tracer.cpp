#include <stdio.h>
#include "dr_api.h"
#include "drmgr.h"

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    dr_set_client_name("Sienna-Locomotive Trace and Triage",
                       "https://github.com/trailofbits/sienna-locomotive/issues");
}
