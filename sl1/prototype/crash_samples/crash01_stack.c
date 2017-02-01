#include <stdio.h>
#include <string.h>

int
set_element(size_t start, size_t destination)
{
  int n = 0;
  char arr[16];
  if (destination < start) {
    return 0;
  }

  n = (int) destination - start;
  while (start < destination) {
    arr[start] = 'X';
    start++;
  }

  return n;
}

int
main(int argc, char *argv[])
{
  int status;
  size_t start, dest;

  if (argc < 3) {
    fprintf(stderr, "Usage: %s [start] [end]\n", argv[0]);
    fprintf(stderr, "\tstart: The start element to write to.\n");
    fprintf(stderr, "\tend: The last element to write to.\n");
    return 1;
  }

  start = atoi(argv[1]);
  dest = atoi(argv[2]);

  status = set_element(start, dest);

  printf("Returned: %d\n", status);

  return 0;
}
