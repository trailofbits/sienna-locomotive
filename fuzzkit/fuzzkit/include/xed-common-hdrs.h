/*BEGIN_LEGAL 
Copyright 2004-2016 Intel Corporation. Use of this code is subject to
the terms and conditions of the What If Pre-Release License Agreement,
which is available here:
https://software.intel.com/en-us/articles/what-if-pre-release-license-agreement
or refer to the LICENSE.txt file.
END_LEGAL */
/// @file xed-common-hdrs.h
/// 



#ifndef _XED_COMMON_HDRS_H_
# define _XED_COMMON_HDRS_H_



#if defined(__FreeBSD__)
# define XED_BSD
#endif
#if defined(__linux__)
# define XED_LINUX
#endif
#if defined(_MSC_VER)
# define XED_WINDOWS
#endif
#if defined(__APPLE__)
# define XED_MAC
#endif


#if defined(XED_DLL)
//  __declspec(dllexport) works with GNU GCC or MS compilers, but not ICC
//  on linux

#  if defined(XED_WINDOWS)
#     define XED_DLL_EXPORT __declspec(dllexport)
#     define XED_DLL_IMPORT __declspec(dllimport)
#  elif defined(XED_LINUX)  || defined(XED_BSD) || defined(XED_MAC)
#     define XED_DLL_EXPORT __attribute__((visibility("default")))
#     define XED_DLL_IMPORT
#  else
#     define XED_DLL_EXPORT
#     define XED_DLL_IMPORT
#  endif
    
#  if defined(XED_BUILD)
    /* when building XED, we export symbols */
#    define XED_DLL_GLOBAL XED_DLL_EXPORT
#  else
    /* when building XED clients, we import symbols */
#    define XED_DLL_GLOBAL XED_DLL_IMPORT
#  endif
#else
# define XED_DLL_EXPORT 
# define XED_DLL_IMPORT
# define XED_DLL_GLOBAL
#endif
    
#endif

