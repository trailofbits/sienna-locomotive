#include "parse.h"

int Parser::parse(const uint8_t *data, size_t size) {
    uint8_t prev = 0;
    uint8_t curr = 0;
    uint32_t count = 0;

    uint8_t *uaf;

    if(size < 1)
        return -1;

    // parser for A terminated strings
    while(count < size) {
        prev = curr;
        curr = *(data+count);

        if(count > 99) {
            std::cout << "case " << (curr - prev) << std::endl;
            switch(curr-prev) {
                case 1:
#ifdef _MSC_VER
					__debugbreak();
#else
					__builtin_trap();
#endif
                    break;
                case 2:
                    uaf = (uint8_t *)malloc(sizeof(uint8_t));
                    *uaf = 0x41;
                    break;
                case 3:
                    free(uaf);
                    break;
                case 4:
                    return (int)*uaf;
                case 5:
                    data -= 1;
                    break;
                default:
                    curr += 0x80;
                    break;
            }
        }

        uint32_t prev_count = count;
        count++;

        if(count < prev_count) {
            break;
        }
    }

    return count;
}