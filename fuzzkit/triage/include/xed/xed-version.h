/*BEGIN_LEGAL 
Copyright 2004-2016 Intel Corporation. Use of this code is subject to
the terms and conditions of the What If Pre-Release License Agreement,
which is available here:
https://software.intel.com/en-us/articles/what-if-pre-release-license-agreement
or refer to the LICENSE.txt file.
END_LEGAL */

#if !defined(_XED_VERSION_H_)
# define _XED_VERSION_H_
#include "xed-common-hdrs.h"

///@ingroup INIT
/// Returns a string representing XED svn commit revision and time stamp.
XED_DLL_EXPORT char const* xed_get_version(void);
///@ingroup INIT
/// Returns a copyright string.
XED_DLL_EXPORT char const* xed_get_copyright(void);
#endif
