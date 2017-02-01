#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int
set_element(char arr[], size_t start, size_t destination)
{
  int n = 0;
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
  char *arr = malloc(16);

  if (argc < 3) {
    fprintf(stderr, "Usage: %s [start] [end]\n", argv[0]);
    fprintf(stderr, "\tstart: The start element to write to.\n");
    fprintf(stderr, "\tend: The last element to write to.\n");
    return 1;
  }

  start = atoi(argv[1]);
  dest = atoi(argv[2]);

  status = set_element(arr, start, dest);

  printf("Returned: %d\n", status);

  return 0;
}
