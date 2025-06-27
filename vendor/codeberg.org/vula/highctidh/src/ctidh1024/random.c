#include <assert.h>
#include <string.h>

#include "random.h"
#include "randombytes.h"
#include "crypto_declassify.h"

#include "int32_sort.h"
#include "int32mask.h"

void
ctidh_fillrandom_default(
  void *const outptr,
  const size_t outsz,
  const uintptr_t context)
{
  (void) context;
  randombytes(outptr, outsz);
}

void random_boundedl1(int8_t *e, const long long w,const long long S, uintptr_t rng_context, ctidh_fillrandom rng_callback)
{
  // standard correspondences:
  // e[0],e[1],...,e[w-1] are w nonnegative integers
  // with sum at most S
  // <=> 1+e[0],1+e[1],...,1+e[w-1] are w positive integers
  // with sum at most S+w
  // <=> 1+e[0],1+e[0]+1+e[1],... are w integers
  // in strictly increasing order
  // between 1 and S+w
  // <=> e[0],1+e[0]+e[1],... are w integers
  // in strictly increasing order
  // between 0 and S+w-1

  assert(w >= 0);
  assert(w < 128);
  assert(S >= 0);
  assert(S < 128);
  if (!w) return;

  const long long rnum = S+w;
  assert(rnum <= 254);
  /* XXX: Microsoft compiler doesn't handle int32_t r[S+w] */
  int32_t r[254];
  memset(r, 0, sizeof(r)); // msan complains if not initalized

  for (;;) { /* rejection-sampling loop */
    rng_callback(r,4*rnum, rng_context);
    for (long long j = 0;j < rnum;++j) r[j] &= ~1;
    for (long long j = 0;j < w;++j) r[j] |= 1;
    int32_sort(r,rnum);
    long long collision = 0;
    for (long long j = 1;j < w;++j)
      collision |= int32mask_zero((r[j]^r[j-1])&~1);

    crypto_declassify(&collision,sizeof collision);
    if (collision) continue;

    for (long long j = 0;j < rnum;++j) r[j] &= 1;
    // now r has Hamming weight w

    for (long long j = 1;j < rnum;++j) r[j] += r[j-1];
    // now r has >=0 copies of 0,
    // >=1 copies of 1, >=1 copies of 2, ..., >=1 copies of w

    for (long long i = 0;i < w;++i) {
      long long numi = 0;
      for (long long j = 0;j < rnum;++j)
        numi -= int32mask_equal(r[j],i);
      e[i] = numi;
    }
    // now e[0]>=0, e[1]>=1, e[2]>=1, ..., e[w-1]>=1
    // and ghost e[w]>=1, not stored
    // e[0]+e[1]+...+e[w] = rnum
    // so e[0]+e[1]+...+e[w-1] <= rnum-1

    for (long long i = 1;i < w;++i)
      --e[i];
    // now e[0]>=0, e[1]>=0, e[2]>=0, ..., e[w-1]>=0
    // sum <= (rnum-1)-(w-1)
    // i.e. sum <= S

    // not done yet: want to allow negative e

    // but simply negating will give zeros too much weight
    // for uniformity, keep e with probability 1/2^z
    // where z is the number of zeros in e

    // speedup: actually keep e with probability 2^zmin/2^z
    // where zmin is minimum possible value of z

    // strategy: start counter at w-S
    // and decrease by 1 for each zero bit
    // and, if negative, flip coin for each zero bit
    long long counter = w-S;

    rng_callback(r,4*((w+31)/32), rng_context);
    long long reject = 0;
    for (long long i = 0;i < w;++i) {
      int32_t rbit = 1&(r[i/32]>>(i&31));
      int32_t eizeromask = int32mask_zero(e[i]);
      counter += eizeromask;
      reject |= int32mask_negative(counter)&eizeromask&rbit;
    }

    crypto_declassify(&reject,sizeof reject);
    if (reject) continue;

    // ok to reuse randomness in r:
    // bits used here are for e[i] nonzero,
    // bits used above are for e[i] zero
    for (long long i = 0;i < w;++i) {
      int32_t rbit = 1&(r[i/32]>>(i&31));
      e[i] ^= -rbit;
      e[i] += rbit;
    }

    return;
  }
}

// -1 if x < y, else 0
static int64_t uint64mask_lessthan(uint64_t x,uint64_t y)
{
  int64_t xy = x^y;
  int64_t c = x-y;
  const int64_t flip = ((int64_t) 1)<<63;
  c ^= xy&(c^x^flip);
  return c>>63;
}

int64_t random_coin(uint64_t num,uint64_t den)
{
  uint8_t buf[32];
  memset(buf, 0, sizeof(buf));
  uint64_t r = 0;

  randombytes(buf,sizeof buf);

  for (long long i = 0;i < 256;++i) {
    uint64_t bit = 1&(buf[i/8]>>(i&7));
    r <<= 1;
    r += bit;
    r ^= (~uint64mask_lessthan(r,den))&(r^(r-den));
  }
  // XXX: speed this up

  return uint64mask_lessthan(r,num);
}
