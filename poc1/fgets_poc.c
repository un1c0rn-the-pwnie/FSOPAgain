#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
  FILE *fp;
  char* buffer = (char*) malloc(0x18);
  fp = fopen("/dev/null", "r");
  printf("libc leak: %p\n", puts);
  puts("Enter your buffer overflow: ");
  read(0, buffer, 0x300);
  fgets(buffer, 8, fp);
  fclose(fp);
  return 0;
}
