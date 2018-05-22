// compile with gcc -DNUM_THREADS=8 -pthread -O3 -o brute simplere-brute.c
// or more threads if possible

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>

#define ASCII(X) ((X) >= 0x20 && (X) <= 0x7F)

uint64_t check1(uint32_t a1, uint16_t a2) {
  uint64_t v5 = a1; // [rsp+Ch] [rbp-10h]
  uint64_t v6 = 1LL; // [rsp+14h] [rbp-8h]
  while ( a2 ) {
    if ( a2 & 1 ) v6 = v5 * v6 % 0xF64BB17D;
    v5 = v5 * v5 % 0xF64BB17D;
    a2 >>= 1;
  }
  return v6; // need 0x6F82C8DC
}

uint16_t check2(uint16_t v5, uint16_t a2) {
  uint16_t v2; // ST16_2
  uint16_t i;
  for ( i = a2; i & v5; i = 2 * (i & v2) ) {
    v2 = v5;
    v5 ^= i;
  }
  return (i | v5); // need 0xA496
}

typedef struct _thread_data_t {
  uint32_t tid;
  uint32_t a1;
  uint16_t a2;
  uint16_t a3;
  uint16_t *a2s;
  uint16_t *a3s;
  uint8_t *xors;
} thread_data_t;

void *thr_func(void *arg) {
  thread_data_t *data = (thread_data_t *)arg;
  for (uint32_t a1 = data->tid + 0x20000000; a1 <= 0x7F000000; a1 += NUM_THREADS) {
    uint8_t a11 = (a1 >> 24)       ;
    uint8_t a12 = (a1 >> 16) & 0xFF;
    uint8_t a13 = (a1 >> 8 ) & 0xFF;
    uint8_t a14 = (a1      ) & 0xFF;
    if (/*ASCII(a11) && */ASCII(a12) && ASCII(a13) && ASCII(a14)) {
      uint16_t *a2 = data->a2s;
      uint16_t *a3 = data->a3s;
      uint8_t *xr = data->xors;
      for (; *a2 != 0; a2++, a3++, xr++) {
        if ((a11 ^ a12 ^ a13 ^ a14 ^ (*xr)) == 22 && check1(a1, *a2) == 0x6F82C8DC) {
          data->a1 = a1;
          data->a2 = *a2;
          data->a3 = *a3;
          pthread_exit(data);
        }
      }
    }
  }
  pthread_exit(NULL);
}

int main() {
  puts("finding all check2 solutions ... ");
  uint16_t a2s[0x10000];
  uint16_t a3s[0x10000];
  uint8_t xors[0x10000];
  uint16_t spos = 0;
  for (uint32_t x = 0x20000000; x <= 0x7F000000; x++) {
    uint16_t a2 = (x >> 16)         ;
    uint16_t a3 = (x      ) & 0xFFFF;
    uint8_t a21 = (a2 >> 8 )       ;
    uint8_t a22 = (a2      ) & 0xFF;
    uint8_t a31 = (a3 >> 8 )       ;
    uint8_t a32 = (a3      ) & 0xFF;
    if (/*ASCII(a21) && */ASCII(a22) && ASCII(a31) && ASCII(a32)) {
      if (check2(a2, a3) == 0xA496) {
        a2s[spos] = a2;
        a3s[spos] = a3;
        xors[spos++] = a21 ^ a22 ^ a31 ^ a32;
      }
    }
  }
  printf("%d solutions\n", spos);
  a2s[spos] = 0;
  a3s[spos] = 0;
  xors[spos] = 0;
  
  puts("finding all check1 solutions ... ");
  pthread_t thr[NUM_THREADS];
  thread_data_t data[NUM_THREADS];
  int rc;
  for (uint64_t tid = 0; tid < NUM_THREADS; tid++) {
    data[tid].tid = tid;
    data[tid].a1 = 0;
    data[tid].a2 = 0;
    data[tid].a3 = 0;
    data[tid].a2s = a2s;
    data[tid].a3s = a3s;
    data[tid].xors = xors;
    if ((rc = pthread_create(&thr[tid], NULL, thr_func, &data[tid]))) {
      fprintf(stderr, "error: pthread_create, rc: %d\n", rc);
      return 1;
    }
  }
  spos = 0;
  for (uint64_t tid = 0; tid < NUM_THREADS; tid++) {
    pthread_join(thr[tid], NULL);
    if (data[tid].a1 != 0) spos++;
  }
  printf("%d solutions\n", spos);
  
  puts("sanity check + flag outputs:");
  for (uint64_t tid = 0; tid < NUM_THREADS; tid++) {
    if (data[tid].a1 != 0) {
      uint8_t a11 = (data[tid].a1 >> 24)       ;
      uint8_t a12 = (data[tid].a1 >> 16) & 0xFF;
      uint8_t a13 = (data[tid].a1 >> 8 ) & 0xFF;
      uint8_t a14 = (data[tid].a1      ) & 0xFF;
      uint8_t a21 = (data[tid].a2 >> 8 )       ;
      uint8_t a22 = (data[tid].a2      ) & 0xFF;
      uint8_t a31 = (data[tid].a3 >> 8 )       ;
      uint8_t a32 = (data[tid].a3      ) & 0xFF;
      if (check1(data[tid].a1, data[tid].a2) == 0x6F82C8DC
          && check2(data[tid].a2, data[tid].a3) == 0xA496) {
        if (ASCII(a11) && ASCII(a12) && ASCII(a13) && ASCII(a14)
            && ASCII(a21) && ASCII(a22) && ASCII(a31) && ASCII(a32)) {
          if (a11 ^ a12 ^ a13 ^ a14 ^ a21 ^ a22 ^ a31 ^ a32 == 22) {
            printf("5o_M@ny_an7i_Rev3rsing_T%c%c%c%c%c%c%c%cs\n",
                a14, a13, a12, a11, a22, a21, a32, a31);
          }
        }
      }
    }
  }
  return 0;
}
