/*BEGIN_LEGAL 
Copyright 2004-2016 Intel Corporation. Use of this code is subject to
the terms and conditions of the What If Pre-Release License Agreement,
which is available here:
https://software.intel.com/en-us/articles/what-if-pre-release-license-agreement
or refer to the LICENSE.txt file.
END_LEGAL */

#if !defined(_XED_GET_TIME_H_)
#   define _XED_GET_TIME_H_

#   include "xed-portability.h"
#   include "xed-types.h"

#   if defined(__INTEL_COMPILER) && __INTEL_COMPILER > 810  && !defined(_M_IA64)
#      include <ia32intrin.h>
#   endif
#   if defined(__INTEL_COMPILER) && __INTEL_COMPILER >= 810  && !defined(_M_IA64)
#      if __INTEL_COMPILER < 1000
#         pragma intrinsic(__rdtsc)
#      endif
#   endif
#   if !defined(__INTEL_COMPILER)
       /* MSVS8 and later */
#      if defined(_MSC_VER) && _MSC_VER >= 1400 && !defined(_M_IA64)
#         include <intrin.h>
#         pragma intrinsic(__rdtsc)
#      endif
#   endif


///xed_get_time() must be compiled with gnu99 on linux to enable the asm()
///statements. If not gnu99, then xed_get_time() returns zero with gcc. GCC
///has no intrinsic for rdtsc. (The default for XED is to compile with
///-std=c99.)  GCC allows __asm__ even under c99!
static XED_INLINE  xed_uint64_t xed_get_time(void) {
    xed_union64_t ticks;
    // __STRICT_ANSI__ comes from the -std=c99
#   if defined(__GNUC__) //&& !defined(__STRICT_ANSI__)
#      if defined(__i386__) || defined(i386) || defined(i686) || defined(__x86_64__)
          __asm__ volatile ("rdtsc":"=a" (ticks.s.lo32), "=d"(ticks.s.hi32));
#         define FOUND_RDTSC
#      endif
#   endif
#   if defined(__INTEL_COMPILER) &&  __INTEL_COMPILER>=810 && !defined(_M_IA64)
       ticks.u64 = __rdtsc();
#      define FOUND_RDTSC
#   endif
#   if !defined(__INTEL_COMPILER)
#      if !defined(FOUND_RDTSC) && defined(_MSC_VER) && _MSC_VER >= 1400 && \
                               !defined(_M_IA64) && !defined(_MANAGED)    /* MSVS7, 8 */
          ticks.u64 = __rdtsc();
#         define FOUND_RDTSC
#      endif
#   endif
#   if !defined(FOUND_RDTSC)
       ticks.u64 = 0;
#   endif
    return ticks.u64;
}

#endif
