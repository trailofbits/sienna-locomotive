#ifndef sl2_dr_client_options_hpp
#define sl2_dr_client_options_hpp

////////////////////////////////////////////////////////////////////////////
// Common drclient options go here

#include "droption.h"

/*! Required, which specific call to target */
static droption_t<std::string> op_target(DROPTION_SCOPE_CLIENT, "t", "", "target",
                                         "Specific call to target.");

/*! Enables Tracking of ReqQueryValueExA/W. Probably never needed for most workflows. */
static droption_t<bool> op_registry(DROPTION_SCOPE_CLIENT, "registry", false,
                                    "Enable Registry Tracking",
                                    "Tracking of RegQuery*() functions");

#endif