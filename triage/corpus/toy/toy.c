#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define BUFSIZE 100

int main(int argc, char *argv) {
    char buf[BUFSIZE] = { 0 };
    FILE *fp;
    fp = fopen("homeland.txt", "r");
    fread(buf, BUFSIZE, 1, fp);
    buf[25] = '\0';

    uint32_t first = buf[0];
    uint32_t second = buf[1];

    if(first * second == 0x1638) {
        printf("%s\n", buf);
        printf("%p\n", buf);
    }

}