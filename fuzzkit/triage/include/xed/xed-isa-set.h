/*BEGIN_LEGAL 
Copyright 2004-2016 Intel Corporation. Use of this code is subject to
the terms and conditions of the What If Pre-Release License Agreement,
which is available here:
https://software.intel.com/en-us/articles/what-if-pre-release-license-agreement
or refer to the LICENSE.txt file.
END_LEGAL */
/// @file xed-isa-set.h


#if !defined(_XED_ISA_SET_H_)
# define _XED_ISA_SET_H_
    
#include "xed-common-hdrs.h"
#include "xed-types.h"
#include "xed-isa-set-enum.h"     /* generated */
#include "xed-chip-enum.h"        /* generated */

/// @ingroup ISASET
/// return 1 if the isa_set is part included in the specified chip, 0
///  otherwise.
XED_DLL_EXPORT xed_bool_t
xed_isa_set_is_valid_for_chip(xed_isa_set_enum_t isa_set,
                              xed_chip_enum_t chip);

    
#endif
