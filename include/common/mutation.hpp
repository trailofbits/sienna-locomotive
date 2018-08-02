#ifndef SL2_MUTATION_HPP
#define SL2_MUTATION_HPP

#include "common/util.h"

// Known values (common boundaries, buffer sizes, overflow values)
#define KNOWN_VALUES1 -128, -2, -1, 0, 1, 2, 4, 8, 10, 16, 32, 64, 100, 127, 128, 255
#define KNOWN_VALUES2 -32768, -129, 256, 512, 1000, 1024, 4096, 32767, 65535
#define KNOWN_VALUES4 -2147483648, -100663046, -32769, 32768, 65536, 100663045, 2147483647, 4294967295
#define KNOWN_VALUES8  -9151314442816848000, -2147483649, 2147483648, 4294967296, 432345564227567365, 18446744073709551615

#define SL2_NUM_STRATEGIES (sizeof(SL2_STRATEGY_TABLE) / sizeof(SL2_STRATEGY_TABLE[0]))

// Represents a custom mutation strategy.
typedef void (*sl2_strategy_t)(uint8_t *buf, size_t size);

extern sl2_strategy_t SL2_STRATEGY_TABLE[];

// Fill the input buffer with 0x41s,
SL2_EXPORT
void strategyAAAA(uint8_t *buf, size_t size);

// Flip a random bit within a random byte in the input buffer.
SL2_EXPORT
void strategyFlipBit(uint8_t *buf, size_t size);

// Repeat a random continuous span of bytes within the input buffer.
SL2_EXPORT
void strategyRepeatBytes(uint8_t *buf, size_t size);

// Reverse the order of a random continuous span of bytes
// within the input buffer.
SL2_EXPORT
void strategyRepeatBytesBackwards(uint8_t *buf, size_t size);

// Delete (null out) a random continuous span of bytes
// within the input buffer.
SL2_EXPORT
void strategyDeleteBytes(uint8_t *buf, size_t size);

// Delete (ASCII zero-out) a random continuous span of bytes
// within the input buffer.
SL2_EXPORT
void strategyDeleteBytesAscii(uint8_t *buf, size_t size);

// Replace a random continuous span of bytes within the input
// buffer with random values.
SL2_EXPORT
void strategyRandValues(uint8_t *buf, size_t size);

// Replace a random continuous span of bytes within the input
// buffer with well-known values (maxes, overflows, etc).
SL2_EXPORT
void strategyKnownValues(uint8_t *buf, size_t size);

// Add or subtract a random well-known value from a random u8/u16/u32/u64.
// Additionally, perform a random byteswap.
SL2_EXPORT
void strategyAddSubKnownValues(uint8_t *buf, size_t size);

// Swap the endiannness of a random u8/u16/u32/u64.
SL2_EXPORT
void strategyEndianSwap(uint8_t *buf, size_t size);

// Mutates the given buffer using a user-selected, pre-defined strategy.
// Returns false if the strategy does not exist or if the buffer is empy
// (`size == 0`).
SL2_EXPORT
bool mutate_buffer_choice(uint8_t *buf, size_t size, uint32_t choice);

// Mutates the given buffer using a random strategy.
// Returns false if the buffer is empty (`size == 0`).
SL2_EXPORT
bool mutate_buffer(uint8_t *buf, size_t size);

// Mutates the given buffer using a user-supplied strategy.
// Returns false if the buffer is empty (`size == 0`).
SL2_EXPORT
bool mutate_buffer_custom(uint8_t *buf, size_t size, sl2_strategy_t strategy);

#endif

