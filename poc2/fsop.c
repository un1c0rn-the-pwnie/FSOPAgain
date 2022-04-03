#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

// compile with: gcc fsop.c -o fsop -fstack-protector-all, because we want make our life harder ;)
void smash_me_baby(FILE* fp) {
  fputc('F', fp);
}

int main() {
  FILE *fp;
  char* buffer = (char*) malloc(0x18);
  fp = fopen("/dev/null", "r");
  printf("libc leak: %p\n", puts);
  puts("Enter your buffer overflow: ");
  read(0, buffer, 0x300);
  puts("Press F to doubt.");
  smash_me_baby(fp);
  fclose(fp);
  return 0;
}
