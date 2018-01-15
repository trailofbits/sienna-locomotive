/*BEGIN_LEGAL 
Copyright 2004-2016 Intel Corporation. Use of this code is subject to
the terms and conditions of the What If Pre-Release License Agreement,
which is available here:
https://software.intel.com/en-us/articles/what-if-pre-release-license-agreement
or refer to the LICENSE.txt file.
END_LEGAL */
/// @file xed-operand-action.h
/// 

#if !defined(_XED_OPERAND_ACTION_H_)
# define _XED_OPERAND_ACTION_H_

#include "xed-types.h"
#include "xed-operand-action-enum.h"

XED_DLL_EXPORT xed_uint_t xed_operand_action_read(const xed_operand_action_enum_t rw);
XED_DLL_EXPORT xed_uint_t xed_operand_action_read_only(const xed_operand_action_enum_t rw);
XED_DLL_EXPORT xed_uint_t xed_operand_action_written(const xed_operand_action_enum_t rw);
XED_DLL_EXPORT xed_uint_t xed_operand_action_written_only(const xed_operand_action_enum_t rw);
XED_DLL_EXPORT xed_uint_t xed_operand_action_read_and_written(const xed_operand_action_enum_t rw);
XED_DLL_EXPORT xed_uint_t xed_operand_action_conditional_read(const xed_operand_action_enum_t rw);
XED_DLL_EXPORT xed_uint_t xed_operand_action_conditional_write(const xed_operand_action_enum_t rw);

#endif

