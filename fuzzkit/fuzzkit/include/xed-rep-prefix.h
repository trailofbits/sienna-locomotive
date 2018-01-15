/*BEGIN_LEGAL 
Copyright 2004-2016 Intel Corporation. Use of this code is subject to
the terms and conditions of the What If Pre-Release License Agreement,
which is available here:
https://software.intel.com/en-us/articles/what-if-pre-release-license-agreement
or refer to the LICENSE.txt file.
END_LEGAL */
/// @file xed-immed.h
/// 

#ifndef _XED_REP_PREFIX_H_
# define _XED_REP_PREFIX_H_

#include "xed-types.h"
#include "xed-common-defs.h"
#include "xed-iclass-enum.h"
/// @name REP-like prefix removal and addition
//@{

/// @ingroup DEC Take an instruction with a REP/REPE/REPNE prefix and
/// return the corresponding xed_iclass_enum_t without that prefix. The
/// return value differs from the other functions in this group: If the
/// input iclass does not have REP/REPNE/REPE prefix, the function returns
/// the original instruction.
XED_DLL_EXPORT xed_iclass_enum_t xed_rep_remove(xed_iclass_enum_t x);

/// @ingroup DEC Take an #xed_iclass_enum_t value without a REPE prefix and
/// return the corresponding #xed_iclass_enum_t with a REPE prefix. If the
/// input instruction cannot have have a REPE prefix, this function returns
/// XED_ICLASS_INVALID.
XED_DLL_EXPORT xed_iclass_enum_t xed_repe_map(xed_iclass_enum_t iclass);

/// @ingroup DEC Take an #xed_iclass_enum_t value without a REPNE prefix
/// and return the corresponding #xed_iclass_enum_t with a REPNE prefix. If
/// the input instruction cannot have a REPNE prefix, this function returns
/// XED_ICLASS_INVALID.
XED_DLL_EXPORT xed_iclass_enum_t xed_repne_map(xed_iclass_enum_t iclass);

/// @ingroup DEC Take an #xed_iclass_enum_t value without a REP prefix and
/// return the corresponding #xed_iclass_enum_t with a REP prefix. If the
/// input instruction cannot have a REP prefix, this function returns
/// XED_ICLASS_INVALID.
XED_DLL_EXPORT xed_iclass_enum_t xed_rep_map(xed_iclass_enum_t iclass);

/// @ingroup DEC Take an #xed_iclass_enum_t value for an instruction with a
/// REP/REPNE/REPE prefix and return the corresponding #xed_iclass_enum_t
/// without that prefix. If the input instruction does not have a
/// REP/REPNE/REPE prefix, this function returns XED_ICLASS_INVALID.
XED_DLL_EXPORT xed_iclass_enum_t xed_norep_map(xed_iclass_enum_t iclass);
//@}
#endif
