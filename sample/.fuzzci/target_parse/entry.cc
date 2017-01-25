#include "../../src/main/parse.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Parser parser;
    parser.parse(data, size);
    return 0;
}