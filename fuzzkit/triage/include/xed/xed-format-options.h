/*BEGIN_LEGAL 
Copyright 2004-2016 Intel Corporation. Use of this code is subject to
the terms and conditions of the What If Pre-Release License Agreement,
which is available here:
https://software.intel.com/en-us/articles/what-if-pre-release-license-agreement
or refer to the LICENSE.txt file.
END_LEGAL */
/// @file xed-format-options.h 


#ifndef _XED_FORMAT_OPTIONS_H_
# define _XED_FORMAT_OPTIONS_H_
#include "xed-types.h"


/// @name Formatting options
//@{

/// Options for the disasembly formatting functions. Set once during
/// initialization by a calling #xed_format_set_options
///  @ingroup PRINT
typedef struct {
    /// by default, XED prints the hex address before any symbolic name for
    /// branch targets. If set to zero, then XED will not print the hex
    /// address before a valid symbolic name.
    unsigned int hex_address_before_symbolic_name; 

    /// Simple XML output format for the Intel syntax disassembly.
    unsigned int xml_a; 
    /// Include flags in the XML formatting (must also supply xml_a)
    unsigned int xml_f; 

    /// omit unit scale "*1" 
    unsigned int omit_unit_scale;

    /// do not sign extend signed immediates 
    unsigned int no_sign_extend_signed_immediates;

    /// write-mask-with-curly-brackets, omit k0
    unsigned int write_mask_curly_k0;
    
    /// lowercase hexidecimal
    xed_bool_t lowercase_hex;

} xed_format_options_t;

/// Optionally, customize the disassembly formatting options by passing 
/// in a #xed_format_options_t structure.
/// @ingroup PRINT
XED_DLL_EXPORT void
xed_format_set_options(xed_format_options_t format_options);
//@}

#endif
