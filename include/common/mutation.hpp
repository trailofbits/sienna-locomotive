#ifndef SL2_MUTATION_HPP
#define SL2_MUTATION_HPP

#include "common/util.h"

// Known values (common boundaries, buffer sizes, overflow values)
#define KNOWN_VALUES1 -128, -2, -1, 0, 1, 2, 4, 8, 10, 16, 32, 64, 100, 127, 128, 255
#define KNOWN_VALUES2 -32768, -129, 256, 512, 1000, 1024, 4096, 32767, 65535
#define KNOWN_VALUES4 -2147483648, -100663046, -32769, 32768, 65536, 100663045, 2147483647, 4294967295
#define KNOWN_VALUES8  -9151314442816848000, -2147483649, 2147483648, 4294967296, 432345564227567365, 18446744073709551615

SL2_EXPORT
DWORD mutate_buffer(uint8_t *buf, size_t size);

#endif

