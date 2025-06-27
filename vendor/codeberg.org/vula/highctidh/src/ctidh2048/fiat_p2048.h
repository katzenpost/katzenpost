#ifndef fiat_p2048_H
#define fiat_p2048_H

#include <stdint.h>
typedef unsigned char fiat_p2048_uint1;
typedef signed char fiat_p2048_int1;
#if defined(__GNUC__) || defined(__clang__)
#  define FIAT_P2048_FIAT_EXTENSION __extension__
#  define FIAT_P2048_FIAT_INLINE __inline__
#else
#  define FIAT_P2048_FIAT_EXTENSION
#  define FIAT_P2048_FIAT_INLINE
#endif

FIAT_P2048_FIAT_EXTENSION typedef signed __int128 fiat_p2048_int128;
FIAT_P2048_FIAT_EXTENSION typedef unsigned __int128 fiat_p2048_uint128;

typedef uint64_t fiat_p2048_montgomery_domain_field_element[32];
typedef uint64_t fiat_p2048_non_montgomery_domain_field_element[32];

static inline void fiat_p2048_addcarryx_u64(uint64_t* out1, fiat_p2048_uint1* out2, fiat_p2048_uint1 arg1, uint64_t arg2, uint64_t arg3) {
  fiat_p2048_uint128 x1;
  uint64_t x2;
  fiat_p2048_uint1 x3;
  x1 = ((arg1 + (fiat_p2048_uint128)arg2) + arg3);
  x2 = (uint64_t)(x1 & UINT64_C(0xffffffffffffffff));
  x3 = (fiat_p2048_uint1)(x1 >> 64);
  *out1 = x2;
  *out2 = x3;
}

static inline void fiat_p2048_subborrowx_u64(uint64_t* out1, fiat_p2048_uint1* out2, fiat_p2048_uint1 arg1, uint64_t arg2, uint64_t arg3) {
  fiat_p2048_int128 x1;
  fiat_p2048_int1 x2;
  uint64_t x3;
  x1 = ((arg2 - (fiat_p2048_int128)arg1) - arg3);
  x2 = (fiat_p2048_int1)(x1 >> 64);
  x3 = (uint64_t)(x1 & UINT64_C(0xffffffffffffffff));
  *out1 = x3;
  *out2 = (fiat_p2048_uint1)(0x0 - x2);
}

static inline void fiat_p2048_mulx_u64(uint64_t* out1, uint64_t* out2, uint64_t arg1, uint64_t arg2) {
  fiat_p2048_uint128 x1;
  uint64_t x2;
  uint64_t x3;
  x1 = ((fiat_p2048_uint128)arg1 * arg2);
  x2 = (uint64_t)(x1 & UINT64_C(0xffffffffffffffff));
  x3 = (uint64_t)(x1 >> 64);
  *out1 = x2;
  *out2 = x3;
}

static inline void fiat_p2048_cmovznz_u64(uint64_t* out1, fiat_p2048_uint1 arg1, uint64_t arg2, uint64_t arg3) {
  fiat_p2048_uint1 x1;
  uint64_t x2;
  uint64_t x3;
  x1 = (!(!arg1));
  x2 = ((fiat_p2048_int1)(0x0 - x1) & UINT64_C(0xffffffffffffffff));
  x3 = ((x2 & arg3) | ((~x2) & arg2));
  *out1 = x3;
}

void fiat_p2048_mul(fiat_p2048_montgomery_domain_field_element out1, const fiat_p2048_montgomery_domain_field_element arg1, const fiat_p2048_montgomery_domain_field_element arg2);
void fiat_p2048_add(fiat_p2048_montgomery_domain_field_element out1, const fiat_p2048_montgomery_domain_field_element arg1, const fiat_p2048_montgomery_domain_field_element arg2);
void fiat_p2048_sub(fiat_p2048_montgomery_domain_field_element out1, const fiat_p2048_montgomery_domain_field_element arg1, const fiat_p2048_montgomery_domain_field_element arg2);
void fiat_p2048_opp(fiat_p2048_montgomery_domain_field_element out1, const fiat_p2048_montgomery_domain_field_element arg1);
void fiat_p2048_selectznz(uint64_t out1[32], fiat_p2048_uint1 arg1, const uint64_t arg2[32], const uint64_t arg3[32]);
void fiat_p2048_square(fiat_p2048_montgomery_domain_field_element out1, const fiat_p2048_montgomery_domain_field_element arg1);

void fiat_p2048_set_one(fiat_p2048_montgomery_domain_field_element out1);
void fiat_p2048_nonzero(uint64_t* out1, const uint64_t arg1[32]);

#endif /* fiat_p2048_H */
