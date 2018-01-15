/*BEGIN_LEGAL 
Copyright 2004-2016 Intel Corporation. Use of this code is subject to
the terms and conditions of the What If Pre-Release License Agreement,
which is available here:
https://software.intel.com/en-us/articles/what-if-pre-release-license-agreement
or refer to the LICENSE.txt file.
END_LEGAL */
/// @file xed-init.h 
/// 




#if !defined(_XED_INIT_H_)
# define _XED_INIT_H_


/// @ingroup INIT
///   This is the call to initialize the XED encode and decode tables. It
///   must be called once before using XED.
void XED_DLL_EXPORT  xed_tables_init(void);

////////////////////////////////////////////////////////////////////////////

#endif
