#include <iostream>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "parse.h"

int main(int argc, char **argv) {
    if(argc < 2) {
        std::cout << "Please provide an input." << std::endl;
        exit(1);
    }

    Parser parser;
    int count = parser.parse((uint8_t *)argv[1], strlen(argv[1]));
    std::cout << count << std::endl;
    return 0;
}