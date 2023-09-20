#include <stdio.h>

int myFunction() {
  int x = 3;
  x += 1;
  return x;
}

int main() {
  printf("Hello there\n");
  printf("General Kenobi %i\n", myFunction());

  return 0;
}
