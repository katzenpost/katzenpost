#ifndef UINTBIG_H
#define UINTBIG_H

#include "uintbig_namespace.h"

#include <stdbool.h>
#include <stdint.h>
#include "annotations.h"

#define UINTBIG_LIMBS ((BITS+63)/64)

typedef struct uintbig {
    uint64_t c[UINTBIG_LIMBS];
} uintbig;

extern const uintbig uintbig_p;
extern const uintbig uintbig_1;
extern const uintbig uintbig_four_sqrt_p;

void uintbig_set(uintbig *x, uint64_t y);

long long uintbig_bit(uintbig const *x, uint64_t k);

long long uintbig_add3(uintbig *const x, uintbig const *const y, uintbig const *const z); /* returns carry */
long long uintbig_sub3(uintbig *const x, uintbig const *const y, uintbig const *const z); /* returns borrow */

void ATTR_INITIALIZE_1st
uintbig_mul3_64(uintbig *const x, uintbig const *const y, const uint64_t z);

static inline long long uintbig_bits_vartime(const uintbig *const x)
{
  long long result = (BITS == 511 ? 512 : BITS);
  while (result > 0 && !uintbig_bit(x,result-1)) --result;
  return result;
}

static inline long long uintbig_uint64_iszero(uint64_t t)
{
  // is t nonzero?
  t |= t>>32;
  // are bottom 32 bits of t nonzero?
  t &= 0xffffffff;
  // is t nonzero? between 0 and 0xffffffff
  t = -t;
  // is t nonzero? 0, or between 2^64-0xffffffff and 2^64-1
  t >>= 63;
  return 1-(long long) t;
}

static inline long long uintbig_iszero(const uintbig *const x)
{
  uint64_t t = 0;
  for (long long i = 0;i < UINTBIG_LIMBS;++i)
    t |= x->c[i];
  return uintbig_uint64_iszero(t);
}

static inline long long uintbig_isequal(const uintbig *const x,const uintbig *const y)
{
  uint64_t t = 0;
  for (long long i = 0;i < UINTBIG_LIMBS;++i)
    t |= (x->c[i])^(y->c[i]);
  return uintbig_uint64_iszero(t);
}

#endif
