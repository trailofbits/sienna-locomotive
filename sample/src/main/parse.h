#include <stdint.h>
#include <stdlib.h>
#include <iostream>

#ifndef PARSE
#define PARSE

class Parser {
public:
    int parse(const uint8_t *data, size_t size);
};

#endif