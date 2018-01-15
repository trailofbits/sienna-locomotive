/*BEGIN_LEGAL 
Copyright 2004-2016 Intel Corporation. Use of this code is subject to
the terms and conditions of the What If Pre-Release License Agreement,
which is available here:
https://software.intel.com/en-us/articles/what-if-pre-release-license-agreement
or refer to the LICENSE.txt file.
END_LEGAL */
/// @file xed-immed.h
/// 

#ifndef _XED_IMMED_H_
# define _XED_IMMED_H_

#include "xed-types.h"
#include "xed-common-defs.h"
#include "xed-util.h"

XED_DLL_EXPORT xed_int64_t xed_immed_from_bytes(xed_int8_t* bytes, xed_uint_t n);
    /*
      Convert an array of bytes representing a Little Endian byte ordering
      of a number (11 22 33 44 55.. 88), in to a a 64b SIGNED number. That gets
      stored in memory in little endian format of course. 

      Input 11 22 33 44 55 66 77 88, 8
      Ouptut 0x8877665544332211  (stored in memory as (lsb) 11 22 33 44 55 66 77 88 (msb))

      Input f0, 1
      Output 0xffff_ffff_ffff_fff0  (stored in memory as f0 ff ff ff   ff ff ff ff)

      Input f0 00, 2
      Output 0x0000_0000_0000_00F0 (stored in memory a f0 00 00 00  00 00 00 00)

      Input 03, 1
      Output 0x0000_0000_0000_0030 (stored in memory a 30 00 00 00  00 00 00 00)
    */


#endif
