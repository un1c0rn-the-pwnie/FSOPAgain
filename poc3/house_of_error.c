#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

// Compile with:
// gcc house_of_error.c -o house_of_error -pie -fstack-protector-all -Wl,-z,relro,-z,now
// We want all protections enabled ;)

void* pwnie_lands[8];

void welcome() {
  puts("~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
  puts("~~ Welcome to pwnie land. ~~");
  puts("~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
  puts("");
  puts("@ Here in pwnie land we have only one rule:");
  puts("@ 1) Ride the heap like a true pwnie and plz stop drugs");
  puts("");
  printf("@ The ASLR god gifted you a present for your adventure: %p\n", puts);
  puts("");
  puts("~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
}

void menu() {
  puts("");
  puts("Press 1 to add a new pwnie land");
  puts("Press 2 to burn your pwnie land");
}

char select_option() {
  char buf[8];
  memset(buf, 0, 8);
  menu();
  printf("> ");
  fgets(buf, 4, stdin);
  return buf[0];
}

void setup() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  // we do not buffer stderr not because we do not care about stderr, but because if we use the stderr symbol then glibc will map stderr into our binary's data section but we have PIE enabled.
  // If stderr is used and it is mapped in our binary's data section then we have either to disable PIE or get a PIE leak.

  for(int i = 0; i<8; i++) pwnie_lands[i] = NULL; // unnecessary but we do it anyway.
  welcome();
}

char findAvailablePwnieLand() {
  for(char i = 0; i<8; i++)
    if(pwnie_lands[i] == NULL)
      return i;
  return -1;
}

void add_pwnie_land() {
  unsigned short pwnie_land_size = 0;
  char pwnie_land_size_buf[32];
  memset(pwnie_land_size_buf, 0 ,32);

  char pwnie_land_address = findAvailablePwnieLand();

  if(pwnie_land_address == -1) {
    puts("You have too many pwnie lands already to work with!");
    return;
  }

  puts("We offer you small and large pwnie lands for all your needs");
  puts("But we advice you large pwnie lands because with this way we can profit more of your slave work");
  printf("> ");

  fgets(pwnie_land_size_buf, 16, stdin);
  pwnie_land_size = (unsigned short)strtol(pwnie_land_size_buf, NULL, 16);
  if(pwnie_land_size > 0x1000) {
    puts("I know that you wouldn't survive such a big pwnie land, so pick a smaller");
    puts("I want you alive for making profits from you.");
    return;
  }

  pwnie_lands[pwnie_land_address] = malloc(pwnie_land_size);
  if(pwnie_lands[pwnie_land_address] == NULL) {
    puts("Pwnie land's resources are too low, sorry you have to die.");
    puts("Auto initiating self destruction...");
    exit(0xdeadbeef);
  }

  puts("Farm your new pwnie land and get me some profits!");
  printf("> ");

  fgets(pwnie_lands[pwnie_land_address], pwnie_land_size + 40, stdin); // give him more farm space if he needs it!
}

void burn_pwnie_land() {
  unsigned short pwnie_land_address = 0;
  char pwnie_land_address_buf[32];
  memset(pwnie_land_address_buf, 0 ,32);

  printf("Tell me slave which pwnie land do you want to burn: ");
  fgets(pwnie_land_address_buf, 16, stdin);

  pwnie_land_address = (unsigned short)strtol(pwnie_land_address_buf, NULL, 16);
  if(pwnie_land_address > 7) {
    puts("Bad pwnie land");
    return;
  }

  if(pwnie_lands[pwnie_land_address] == NULL) {
    puts("Bad pwnie land.");
    return;
  }

  free(pwnie_lands[pwnie_land_address]);
  pwnie_lands[pwnie_land_address] = NULL;
  puts("Your pwnie land burned!");
}

int main() {
  char option = 0;

  setup();

  while(1) {
    option = select_option();
    switch(option) {
      case '1': {
        add_pwnie_land();
        break;
      }
      case '2': {
        burn_pwnie_land();
        break;
      }
      default: {
        puts("Sorry you are not allowed to leave, you are my slave.");
        break;
      }
    }
  }

  // If he tries to escape somehow we will punish him.
  exit(0xbadb01);
  return 0;
}
