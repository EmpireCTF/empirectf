// compile with
// gcc -O3 -o queens queens.c

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
 
typedef uint32_t uint;
uint full, *qs, count = 0, nn;
 
void solve(uint d, uint c, uint l, uint r) {
  uint b, a, *s;
  if (!d) {
    count++;
#if 1
    for (a = 0; a < nn; a++)
      for (b = 0; b < nn; b++)
        if (b == qs[a]) printf("1,");
        else printf("0,");
    putchar('\n');
#endif
    return;
  }
 
  a = (c | (l <<= 1) | (r >>= 1)) & full;
  if (a != full)
    for (*(s = qs + --d) = 0, b = 1; b <= full; (*s)++, b <<= 1)
      if (!(b & a)) solve(d, b|c, b|l, b|r);
}
 
int main(int n, char **argv) {
  if (n <= 1 || (nn = atoi(argv[1])) <= 0) nn = 8;
  
  qs = calloc(nn, sizeof(int));
  full = (1U << nn) - 1;
  
  solve(nn, 0, 0, 0);
  return 0;
}
