#ifndef int64mask_h
#define int64mask_h

#include <inttypes.h>

/* masks are -1 if condition holds, 0 if not */

static inline int64_t int64mask_negative(int64_t x)
{
  return x>>63; /* requires -fwrapv */
}

static inline int64_t int64mask_nonzero(int64_t x)
{
  return int64mask_negative(x)|int64mask_negative(-x);
}

static inline int64_t int64mask_zero(int64_t x)
{
  return ~int64mask_nonzero(x);
}

static inline int64_t int64mask_equal(int64_t x,int64_t y)
{
  return int64mask_zero(x^y);
}

#endif
