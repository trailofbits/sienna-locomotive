#include <stdint.h>
#include <random>

#include <Windows.h>

#include "dr_api.h"

#include "common/mutation.hpp"
#include "common/sl2_dr_client.hpp"

/*
  Mutation strategies. The server selects one each time the fuzzing harness requests mutated bytes
*/

static void strategyAAAA(unsigned char *buf, size_t size)
{
    memset(buf, 'A', size);
}

static void strategyFlipBit(unsigned char *buf, size_t size)
{
    size_t pos = dr_get_random_value(size);
    unsigned char byte = buf[pos];

    unsigned char mask = 1 << dr_get_random_value(8);
    buf[pos] = byte ^ mask;
}

static void strategyRepeatBytes(unsigned char *buf, size_t size)
{
    // pos -> zero to second to last byte
    size_t pos = dr_get_random_value(size - 1);

    // repeat_length -> 1 to (remaining_size - 1)
    size_t size_m2 = size - 2;
    size_t repeat_length = 0;
    if (size_m2 > pos) {
        repeat_length = dr_get_random_value(size_m2 - pos);
    }
    repeat_length++;

    // set start and end
    size_t curr_pos = pos + repeat_length;
    size_t end = dr_get_random_value(size - curr_pos);
    end += curr_pos + 1;

    while (curr_pos < end) {
        buf[curr_pos] = buf[pos];
        curr_pos++;
        pos++;
    }
}

static void strategyRepeatBytesBackward(unsigned char *buf, size_t size)
{
    size_t start = dr_get_random_value(size - 1);
    size_t end = start + dr_get_random_value((size + 1) - start);

    std::reverse(buf + start, buf + end);
}

static void strategyDeleteBytes(unsigned char *buf, size_t size)
{
    // pos -> zero to second to last byte
    size_t pos = 0;
    if (size > 1) {
        pos = dr_get_random_value(size - 1);
    }

    // delete_length -> 1 to (remaining_size - 1)
    size_t size_m2 = size - 2;
    size_t delete_length = 0;
    if (size_m2 > pos) {
        delete_length = dr_get_random_value(size_m2 - pos);
    }
    delete_length++;

    for (size_t i=0; i<delete_length; i++) {
        buf[pos+i] = 0;
    }
}

static void strategyRandValues(unsigned char *buf, size_t size)
{
    size_t rand_size = 0;
    size_t max = 0;
    while (max < 1) {
        // rand_size -> 1, 2, 4, 8
        rand_size = (size_t) pow(2, dr_get_random_value(4));
        max = (size + 1);
        max -= rand_size;
    }

    // pos -> zero to ((size + 1) - rand_size)
    // e.g. buf size is 16, rand_size is 8
    // max will be from 0 to 9 guanteeing a
    // pos that will fit into the buffer
    size_t pos = dr_get_random_value(max);

    for (size_t i=0; i<rand_size; i++) {
        unsigned char mut = dr_get_random_value(256);
        buf[pos + i] = mut;
    }
}

static void strategyKnownValues(unsigned char *buf, size_t size)
{
    int8_t values1[] = { KNOWN_VALUES1 };
    int16_t values2[] = { KNOWN_VALUES1, KNOWN_VALUES2 };
    int32_t values4[] = { KNOWN_VALUES1, KNOWN_VALUES2, KNOWN_VALUES4 };
    int64_t values8[] = { KNOWN_VALUES1, KNOWN_VALUES2, KNOWN_VALUES4, KNOWN_VALUES8 };

    size_t rand_size = 0;
    size_t max = 0;
    while (max < 1) {
        // size -> 1, 2, 4, 8
        rand_size = (size_t) pow(2, dr_get_random_value(4));
        max = (size + 1);
        max -= rand_size;
    }

    // pos -> zero to ((size + 1) - rand_size)
    // e.g. buf size is 16, rand_size is 8
    // max will be from 0 to 9 guaranteeing a
    // pos that will fit into the buffer
    size_t pos = dr_get_random_value(max);
    bool endian = dr_get_random_value(2);

    size_t selection = 0;
    switch (rand_size) {
        case 1:
            selection = dr_get_random_value(sizeof(values1) / sizeof(values1[0]));
            // nibble endianness, because sim cards
            values1[selection] = endian ? values1[selection] >> 4 | values1[selection] << 4 : values1[selection];
            *(uint8_t *)(buf+pos) = values1[selection];
            break;
        case 2:
            selection = dr_get_random_value(sizeof(values2) / sizeof(values2[0]));
            values2[selection] = endian ? _byteswap_ushort(values2[selection]) : values2[selection];
            *(uint16_t *)(buf+pos) = values2[selection];
            break;
        case 4:
            selection = dr_get_random_value(sizeof(values4) / sizeof(values4[0]));
            values4[selection] = endian ? _byteswap_ulong(values4[selection]) : values4[selection];
            *(uint32_t *)(buf+pos) = values4[selection];
            break;
        case 8:
            selection = dr_get_random_value(sizeof(values8) / sizeof(values8[0]));
            values8[selection] = endian ? _byteswap_uint64(values8[selection]) : values8[selection];
            *(uint64_t *)(buf+pos) = values8[selection];
            break;
        default:
            strategyAAAA(buf, size);
            break;
    }
}

static void strategyAddSubKnownValues(unsigned char *buf, size_t size)
{
    int8_t values1[] = { KNOWN_VALUES1 };
    int16_t values2[] = { KNOWN_VALUES1, KNOWN_VALUES2 };
    int32_t values4[] = { KNOWN_VALUES1, KNOWN_VALUES2, KNOWN_VALUES4 };
    int64_t values8[] = { KNOWN_VALUES1, KNOWN_VALUES2, KNOWN_VALUES4, KNOWN_VALUES8 };

    size_t rand_size = 0;
    size_t max = 0;
    while (max < 1) {
        // size -> 1, 2, 4, 8
        rand_size = (size_t) pow(2, dr_get_random_value(4));
        max = (size + 1) - rand_size;
    }

    // pos -> zero to ((size + 1) - rand_size)
    // e.g. buf size is 16, rand_size is 8
    // max will be from 0 to 9 guaranteeing a
    // pos that will fit into the buffer
    size_t pos = dr_get_random_value(max);
    bool endian = dr_get_random_value(2);

    unsigned char sub = 1;
    if (dr_get_random_value(2)) {
        sub = -1;
    }

    size_t selection = 0;
    switch (rand_size) {
        case 1:
            selection = dr_get_random_value(sizeof(values1) / sizeof(values1[0]));
            // nibble endianness, because sim cards
            values1[selection] = endian ? values1[selection] >> 4 | values1[selection] << 4 : values1[selection];
            *(uint8_t *)(buf+pos) += sub * values1[selection];
            break;
        case 2:
            selection = dr_get_random_value(sizeof(values2) / sizeof(values2[0]));
            values2[selection] = endian ? _byteswap_ushort(values2[selection]) : values2[selection];
            *(uint16_t *)(buf+pos) += sub * values2[selection];
            break;
        case 4:
            selection = dr_get_random_value(sizeof(values4) / sizeof(values4[0]));
            values4[selection] = endian ? _byteswap_ulong(values4[selection]) : values4[selection];
            *(uint32_t *)(buf+pos) += sub * values4[selection];
            break;
        case 8:
            selection = dr_get_random_value(sizeof(values8) / sizeof(values8[0]));
            values8[selection] = endian ? _byteswap_uint64(values8[selection]) : values8[selection];
            *(uint64_t *)(buf+pos) += sub * values8[selection];
            break;
        default:
            strategyAAAA(buf, size);
            break;
    }
}

static void strategyEndianSwap(unsigned char *buf, size_t size)
{
    size_t rand_size = 0;
    size_t max = 0;
    while (max < 1) {
        // size -> 1, 2, 4, 8
        rand_size = (size_t) pow(2, dr_get_random_value(4));
        max = (size + 1) - rand_size;
    }

    // pos -> zero to ((size + 1) - rand_size)
    // e.g. buf size is 16, rand_size is 8
    // max will be from 0 to 9 guaranteeing a
    // pos that will fit into the buffer
    size_t pos = dr_get_random_value(max);

    switch (rand_size) {
        case 1:
            // nibble endianness, because sim cards
            *(uint8_t *)(buf+pos) = *(uint8_t *)(buf+pos) >> 4 | *(uint8_t *)(buf+pos) << 4;
            break;
        case 2:
            *(uint16_t *)(buf+pos) = _byteswap_ushort(*(uint16_t *)(buf+pos));
            break;
        case 4:
            *(uint32_t *)(buf+pos) = _byteswap_ulong(*(uint32_t *)(buf+pos));
            break;
        case 8:
            *(uint64_t *)(buf+pos) = _byteswap_uint64(*(uint64_t *)(buf+pos));
            break;
        default:
            strategyAAAA(buf, size);
            break;
    }
}

/* Selects a mutations strategy at random */
__declspec(dllexport) DWORD mutate_buffer(unsigned char *buf, size_t size)
{
    // afl for inspiration
    if (size == 0) {
        return 0;
    }

    DWORD choice = dr_get_random_value(8);

    switch (choice) {
        case 0:
            strategyFlipBit(buf, size);
            break;
        case 1:
            strategyRandValues(buf, size);
            break;
        case 2:
            strategyRepeatBytes(buf, size);
            break;
        case 3:
            strategyKnownValues(buf, size);
            break;
        case 4:
            strategyAddSubKnownValues(buf, size);
            break;
        case 5:
            strategyEndianSwap(buf, size);
            break;
        case 6:
            strategyDeleteBytes(buf, size);
            break;
        case 7:
            strategyRepeatBytesBackward(buf, size);
            break;
        default:
            strategyAAAA(buf, size);
            break;
    }

    // TODO(ww): Additional strategies:
    // insert bytes
    // move bytes
    // add random bytes to space
    // inject random NULL(s)

    return 0;
}
