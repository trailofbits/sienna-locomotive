#include <cstdint>
#include <random>

#include "common/sl2_dr_client.hpp"
#include "common/mutation.hpp"

// TODO(ww): Additional strategies:
// insert bytes
// move bytes
// add random bytes to space
sl2_strategy_t SL2_STRATEGY_TABLE[] = {
    // NOTE(ww): We probably don't need to use this.
    // Some of the other strategies call it as a fallback.
    // strategyAAAA,
    strategyFlipBit,          strategyRandValues,
    strategyRepeatBytes,      strategyRepeatBytesBackwards,
    strategyKnownValues,      strategyAddSubKnownValues,
    strategyEndianSwap,       strategyDeleteBytes,
    strategyDeleteBytesAscii,
};

SL2_EXPORT
void strategyAAAA(uint8_t *buf, size_t size) {
  memset(buf, 'A', size);
}

SL2_EXPORT
void strategyFlipBit(uint8_t *buf, size_t size) {
  size_t pos = dr_get_random_value((uint)size);
  buf[pos] ^= (1 << dr_get_random_value(8));
}

SL2_EXPORT
void strategyRepeatBytes(uint8_t *buf, size_t size) {
  // pos -> zero to second to last byte
  size_t pos = dr_get_random_value((uint)(size - 1));

  // repeat_length -> 1 to (remaining_size - 1)
  size_t size_m2 = size - 2;
  size_t repeat_length = 0;
  if (size_m2 > pos) {
    repeat_length = dr_get_random_value((uint)(size_m2 - pos));
  }
  repeat_length++;

  // set start and end
  size_t curr_pos = pos + repeat_length;
  size_t end = dr_get_random_value((uint)(size - curr_pos));
  end += curr_pos + 1;

  while (curr_pos < end) {
    buf[curr_pos] = buf[pos];
    curr_pos++;
    pos++;
  }
}

SL2_EXPORT
void strategyRepeatBytesBackwards(uint8_t *buf, size_t size) {
  size_t start = dr_get_random_value((uint)(size - 1));
  size_t end = start + dr_get_random_value((uint)((size + 1) - start));

  std::reverse(buf + start, buf + end);
}

SL2_EXPORT
void strategyDeleteBytes(uint8_t *buf, size_t size) {
  size_t start = dr_get_random_value((uint)(size - 1));
  size_t count = dr_get_random_value((uint)((size + 1) - start));

  memset(buf + start, 0, count);
}

SL2_EXPORT
void strategyDeleteBytesAscii(uint8_t *buf, size_t size) {
  size_t start = dr_get_random_value((uint)(size - 1));
  size_t count = dr_get_random_value((uint)((size + 1) - start));

  memset(buf + start, '0', count);
}

SL2_EXPORT
void strategyRandValues(uint8_t *buf, size_t size) {
  size_t rand_size;
  do {
    rand_size = (size_t)1 << dr_get_random_value(4);
  } while (size < rand_size);
  size_t max = (size + 1) - rand_size;
  size_t pos = dr_get_random_value((uint)max);

  for (size_t i = 0; i < rand_size; i++) {
    uint8_t mut = dr_get_random_value(UINT8_MAX + 1);
    buf[pos + i] = mut;
  }
}

SL2_EXPORT
void strategyKnownValues(uint8_t *buf, size_t size) {
  int8_t values1[] = {KNOWN_VALUES1};
  int16_t values2[] = {KNOWN_VALUES1, KNOWN_VALUES2};
  int32_t values4[] = {KNOWN_VALUES1, KNOWN_VALUES2, KNOWN_VALUES4};
  int64_t values8[] = {KNOWN_VALUES1, KNOWN_VALUES2, KNOWN_VALUES4, KNOWN_VALUES8};

  size_t rand_size;
  do {
    rand_size = (size_t)1 << dr_get_random_value(4);
  } while (size < rand_size);
  size_t max = (size + 1) - rand_size;
  size_t pos = dr_get_random_value((uint)max);
  bool endian = dr_get_random_value(2);

  // pos -> zero to ((size + 1) - rand_size)
  // e.g. buf size is 16, rand_size is 8
  // max will be from 0 to 9 guanteeing a
  // pos that will fit into the buffer

  size_t selection = 0;
  switch (rand_size) {
  case 1:
    selection = dr_get_random_value(sizeof(values1) / sizeof(values1[0]));
    // nibble endianness, because sim cards
    values1[selection] =
        endian ? values1[selection] >> 4 | values1[selection] << 4 : values1[selection];
    *(uint8_t *)(buf + pos) = values1[selection];
    break;
  case 2:
    selection = dr_get_random_value(sizeof(values2) / sizeof(values2[0]));
    values2[selection] = endian ? _byteswap_ushort(values2[selection]) : values2[selection];
    *(uint16_t *)(buf + pos) = values2[selection];
    break;
  case 4:
    selection = dr_get_random_value(sizeof(values4) / sizeof(values4[0]));
    values4[selection] = endian ? _byteswap_ulong(values4[selection]) : values4[selection];
    *(uint32_t *)(buf + pos) = values4[selection];
    break;
  case 8:
    selection = dr_get_random_value(sizeof(values8) / sizeof(values8[0]));
    values8[selection] = endian ? _byteswap_uint64(values8[selection]) : values8[selection];
    *(uint64_t *)(buf + pos) = values8[selection];
    break;
  default:
    strategyAAAA(buf, size);
    break;
  }
}

SL2_EXPORT
void strategyAddSubKnownValues(uint8_t *buf, size_t size) {
  int8_t values1[] = {KNOWN_VALUES1};
  int16_t values2[] = {KNOWN_VALUES1, KNOWN_VALUES2};
  int32_t values4[] = {KNOWN_VALUES1, KNOWN_VALUES2, KNOWN_VALUES4};
  int64_t values8[] = {KNOWN_VALUES1, KNOWN_VALUES2, KNOWN_VALUES4, KNOWN_VALUES8};

  size_t rand_size;
  do {
    rand_size = (size_t)1 << dr_get_random_value(4);
  } while (size < rand_size);
  size_t max = (size + 1) - rand_size;
  size_t pos = dr_get_random_value((uint)max);
  bool endian = dr_get_random_value(2);
  uint8_t sub = dr_get_random_value(2) ? -1 : 1;
  size_t selection = 0;

  switch (rand_size) {
  case 1:
    selection = dr_get_random_value(sizeof(values1) / sizeof(values1[0]));
    // nibble endianness, because sim cards
    values1[selection] =
        endian ? values1[selection] >> 4 | values1[selection] << 4 : values1[selection];
    *(uint8_t *)(buf + pos) += sub * values1[selection];
    break;
  case 2:
    selection = dr_get_random_value(sizeof(values2) / sizeof(values2[0]));
    values2[selection] = endian ? _byteswap_ushort(values2[selection]) : values2[selection];
    *(uint16_t *)(buf + pos) += sub * values2[selection];
    break;
  case 4:
    selection = dr_get_random_value(sizeof(values4) / sizeof(values4[0]));
    values4[selection] = endian ? _byteswap_ulong(values4[selection]) : values4[selection];
    *(uint32_t *)(buf + pos) += sub * values4[selection];
    break;
  case 8:
    selection = dr_get_random_value(sizeof(values8) / sizeof(values8[0]));
    values8[selection] = endian ? _byteswap_uint64(values8[selection]) : values8[selection];
    *(uint64_t *)(buf + pos) += sub * values8[selection];
    break;
  default:
    strategyAAAA(buf, size);
    break;
  }
}

SL2_EXPORT
void strategyEndianSwap(uint8_t *buf, size_t size) {
  size_t rand_size;
  do {
    rand_size = (size_t)1 << dr_get_random_value(4);
  } while (size < rand_size);
  size_t max = (size + 1) - rand_size;
  size_t pos = dr_get_random_value((uint)max);

  switch (rand_size) {
  case 1:
    // nibble endianness, because sim cards
    *(uint8_t *)(buf + pos) = *(uint8_t *)(buf + pos) >> 4 | *(uint8_t *)(buf + pos) << 4;
    break;
  case 2:
    *(uint16_t *)(buf + pos) = _byteswap_ushort(*(uint16_t *)(buf + pos));
    break;
  case 4:
    *(uint32_t *)(buf + pos) = _byteswap_ulong(*(uint32_t *)(buf + pos));
    break;
  case 8:
    *(uint64_t *)(buf + pos) = _byteswap_uint64(*(uint64_t *)(buf + pos));
    break;
  default:
    strategyAAAA(buf, size);
    break;
  }
}

/**
 * Applies the mutation strategy given by the index
 * @param buf - pointer to the buffer to be mutated
 * @param size - number of bytes to mutate
 * @param choice - index of the strategy to use
 * @return bool indicating success
 */
static bool mutate_buffer_choice(uint8_t *buf, size_t size, uint32_t choice) {
  if (size == 0 || choice > SL2_NUM_STRATEGIES - 1) {
    return false;
  }

  SL2_STRATEGY_TABLE[choice](buf, size);

  return true;
}

/**
 * Allows directly passing in a specific strategy to be applied
 * @param buf - pointer to the buffer to be mutated
 * @param size - number of bytes to mutate
 * @param strategy - function pointer to the strategy
 * @return bool indicating success
 */
static bool mutate_buffer_custom(uint8_t *buf, size_t size, sl2_strategy_t strategy) {
  if (size == 0) {
    return false;
  }

  strategy(buf, size);

  return true;
}

SL2_EXPORT
bool do_mutation(sl2_mutation *mutation) {
  mutation->mut_type = dr_get_random_value(SL2_NUM_STRATEGIES);

  return mutate_buffer_choice(mutation->buffer, mutation->bufsize, mutation->mut_type);
}

SL2_EXPORT
bool do_mutation_custom(sl2_mutation *mutation, sl2_strategy_t strategy) {
  mutation->mut_type = SL2_CUSTOM_STRATEGY;

  return mutate_buffer_custom(mutation->buffer, mutation->bufsize, strategy);
}
