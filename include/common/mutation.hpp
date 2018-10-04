#ifndef SL2_MUTATION_HPP
#define SL2_MUTATION_HPP

#include "common/util.h"
#include "server.hpp"

// Known values (common boundaries, buffer sizes, overflow values)
#define KNOWN_VALUES1 -128, -2, -1, 0, 1, 2, 4, 8, 10, 16, 32, 64, 100, 127, 128, 255
#define KNOWN_VALUES2 -32768, -129, 256, 512, 1000, 1024, 4096, 32767, 65535
#define KNOWN_VALUES4 -2147483648, -100663046, -32769, 32768, 65536, 100663045, 2147483647, 4294967295
#define KNOWN_VALUES8  -9151314442816848000, -2147483649, 2147483648, 4294967296, 432345564227567365, 18446744073709551615

#define SL2_CUSTOM_STRATEGY (0xFFFFFFFF)

/**
 * Represents a custom mutation strategy.
 */
typedef void (*sl2_strategy_t)(uint8_t *buf, size_t size);

extern sl2_strategy_t SL2_STRATEGY_TABLE[];

/**
 *  Fill the input buffer with 0x41s,
 * @param buf The buffer to mutate
 * @param size the size of the buffer to be mutated
 */
SL2_EXPORT
void strategyAAAA(uint8_t *buf, size_t size);

/**
 *  Flip a random bit within a random byte in the input buffer.
 * @param buf The buffer to mutate
 * @param size the size of the buffer to be mutated
 */
SL2_EXPORT
void strategyFlipBit(uint8_t *buf, size_t size);

/**
 *  Repeat a random continuous span of bytes within the input buffer.
 * @param buf The buffer to mutate
 * @param size the size of the buffer to be mutated
 */
SL2_EXPORT
void strategyRepeatBytes(uint8_t *buf, size_t size);


/**
 * Reverse the order of a random continuous span of bytes within the input buffer.
 * @param buf The buffer to mutate
 * @param size the size of the buffer to be mutated
 */
SL2_EXPORT
void strategyRepeatBytesBackwards(uint8_t *buf, size_t size);


/**
 * Delete (null out) a random continuous span of bytes within the input buffer.
 * @param buf The buffer to mutate
 * @param size the size of the buffer to be mutated
 */
SL2_EXPORT
void strategyDeleteBytes(uint8_t *buf, size_t size);


/**
 * Delete (ASCII zero-out) a random continuous span of bytes within the input buffer.
 * @param buf The buffer to mutate
 * @param size the size of the buffer to be mutated
 */
SL2_EXPORT
void strategyDeleteBytesAscii(uint8_t *buf, size_t size);


/**
 * Replace a random continuous span of bytes within the input buffer with random values.
 * @param buf The buffer to mutate
 * @param size the size of the buffer to be mutated
 */
SL2_EXPORT
void strategyRandValues(uint8_t *buf, size_t size);


/**
 * Replace a random continuous span of bytes within the input buffer with well-known values (maxes, overflows, etc).
 * @param buf The buffer to mutate
 * @param size the size of the buffer to be mutated
 */
SL2_EXPORT
void strategyKnownValues(uint8_t *buf, size_t size);


/**
 * Add or subtract a random well-known value from a random u8/u16/u32/u64. Additionally, perform a random byteswap.
 * @param buf The buffer to mutate
 * @param size the size of the buffer to be mutated
 */
SL2_EXPORT
void strategyAddSubKnownValues(uint8_t *buf, size_t size);

/**
 *  Swap the endiannness of a random u8/u16/u32/u64.
 * @param buf The buffer to mutate
 * @param size the size of the buffer to be mutated
 */
SL2_EXPORT
void strategyEndianSwap(uint8_t *buf, size_t size);


/**
 * Mutates the buffer within the given `mutation`. Uses the `mutation->mut_type` to indicate which mutation was performed.
 * @param mutation
 * @return
 */
SL2_EXPORT
bool do_mutation(sl2_mutation *mutation);


/**
 * Mutates the buffer with `mutation` using `strategy`. Sets `mutation->mut_type` to `SL2_CUSTOM_STRATEGY`.
 * @param mutation
 * @param strategy
 * @return
 */
SL2_EXPORT
bool do_mutation_custom(sl2_mutation *mutation, sl2_strategy_t strategy);

#endif

