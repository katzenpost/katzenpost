#ifndef int32mask_h
#define int32mask_h

#include <inttypes.h>

/* masks are -1 if condition holds, 0 if not */

static inline int32_t int32mask_negative(int32_t x)
{
  return x>>31; /* requires -fwrapv */
}

static inline int32_t int32mask_nonzero(int32_t x)
{
  return int32mask_negative(x)|int32mask_negative(-x);
}

static inline int32_t int32mask_zero(int32_t x)
{
  return ~int32mask_nonzero(x);
}

static inline int32_t int32mask_equal(int32_t x,int32_t y)
{
  return int32mask_zero(x^y);
}

#endif
