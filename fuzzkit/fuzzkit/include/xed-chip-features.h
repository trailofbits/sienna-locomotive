/*BEGIN_LEGAL 
Copyright 2004-2016 Intel Corporation. Use of this code is subject to
the terms and conditions of the What If Pre-Release License Agreement,
which is available here:
https://software.intel.com/en-us/articles/what-if-pre-release-license-agreement
or refer to the LICENSE.txt file.
END_LEGAL */

#if !defined(_XED_CHIP_FEATURES_H_)
# define _XED_CHIP_FEATURES_H_
    
#include "xed-common-hdrs.h"
#include "xed-types.h"
#include "xed-isa-set-enum.h"     /* generated */
#include "xed-chip-enum.h"        /* generated */

/// @ingroup ISASET
typedef struct 
{
    xed_uint64_t f1;
    xed_uint64_t f2;
    xed_uint64_t f3;
} xed_chip_features_t;


/// fill in the contents of p with the vector of chip features.
XED_DLL_EXPORT void
xed_get_chip_features(xed_chip_features_t* p, xed_chip_enum_t chip);

/// present = 1 to turn the feature on. present=0 to remove the feature.
XED_DLL_EXPORT void
xed_modify_chip_features(xed_chip_features_t* p, xed_isa_set_enum_t isa_set, xed_bool_t present);

    
#endif
