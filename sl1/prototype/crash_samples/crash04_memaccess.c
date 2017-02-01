#include <stdio.h>

int
main(int argc, char *argv[])
{
  int *p = 0, accum = 0;

  do {
    accum += *p++;
  } while(p != 0);

  return 0;
}
