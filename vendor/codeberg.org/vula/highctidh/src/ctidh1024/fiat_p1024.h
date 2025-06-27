#ifndef fiat_p1024_H
#define fiat_p1024_H

#include <stdint.h>
typedef unsigned char fiat_p1024_uint1;
typedef signed char fiat_p1024_int1;
#if defined(__GNUC__) || defined(__clang__)
#  define FIAT_P1024_FIAT_EXTENSION __extension__
#  define FIAT_P1024_FIAT_INLINE __inline__
#else
#  define FIAT_P1024_FIAT_EXTENSION
#  define FIAT_P1024_FIAT_INLINE
#endif

FIAT_P1024_FIAT_EXTENSION typedef signed __int128 fiat_p1024_int128;
FIAT_P1024_FIAT_EXTENSION typedef unsigned __int128 fiat_p1024_uint128;

typedef uint64_t fiat_p1024_montgomery_domain_field_element[16];
typedef uint64_t fiat_p1024_non_montgomery_domain_field_element[16];

void fiat_p1024_mul(fiat_p1024_montgomery_domain_field_element out1, const fiat_p1024_montgomery_domain_field_element arg1, const fiat_p1024_montgomery_domain_field_element arg2);
void fiat_p1024_square(fiat_p1024_montgomery_domain_field_element out1, const fiat_p1024_montgomery_domain_field_element arg1);
void fiat_p1024_add(fiat_p1024_montgomery_domain_field_element out1, const fiat_p1024_montgomery_domain_field_element arg1, const fiat_p1024_montgomery_domain_field_element arg2);
void fiat_p1024_sub(fiat_p1024_montgomery_domain_field_element out1, const fiat_p1024_montgomery_domain_field_element arg1, const fiat_p1024_montgomery_domain_field_element arg2);
void fiat_p1024_opp(fiat_p1024_montgomery_domain_field_element out1, const fiat_p1024_montgomery_domain_field_element arg1);

static inline void fiat_p1024_cmovznz_u64(uint64_t* out1, const fiat_p1024_uint1 arg1, const uint64_t arg2, const uint64_t arg3) {
  const fiat_p1024_uint1 x1 = (!(!arg1));
  const uint64_t x2 = ((fiat_p1024_int1)(0x0 - x1) & UINT64_C(0xffffffffffffffff));
  *out1 = ((x2 & arg3) | ((~x2) & arg2));
}

/*
 * The function fiat_p1024_selectznz is a multi-limb conditional select.
 *
 * Postconditions:
 *   out1 = (if arg1 = 0 then arg2 else arg3)
 */
static inline void fiat_p1024_selectznz(uint64_t out1[16], fiat_p1024_uint1 arg1, const uint64_t arg2[16], const uint64_t arg3[16]) {
  uint64_t x1;
  uint64_t x2;
  uint64_t x3;
  uint64_t x4;
  uint64_t x5;
  uint64_t x6;
  uint64_t x7;
  uint64_t x8;
  uint64_t x9;
  uint64_t x10;
  uint64_t x11;
  uint64_t x12;
  uint64_t x13;
  uint64_t x14;
  uint64_t x15;
  uint64_t x16;
  fiat_p1024_cmovznz_u64(&x1, arg1, (arg2[0]), (arg3[0]));
  fiat_p1024_cmovznz_u64(&x2, arg1, (arg2[1]), (arg3[1]));
  fiat_p1024_cmovznz_u64(&x3, arg1, (arg2[2]), (arg3[2]));
  fiat_p1024_cmovznz_u64(&x4, arg1, (arg2[3]), (arg3[3]));
  fiat_p1024_cmovznz_u64(&x5, arg1, (arg2[4]), (arg3[4]));
  fiat_p1024_cmovznz_u64(&x6, arg1, (arg2[5]), (arg3[5]));
  fiat_p1024_cmovznz_u64(&x7, arg1, (arg2[6]), (arg3[6]));
  fiat_p1024_cmovznz_u64(&x8, arg1, (arg2[7]), (arg3[7]));
  fiat_p1024_cmovznz_u64(&x9, arg1, (arg2[8]), (arg3[8]));
  fiat_p1024_cmovznz_u64(&x10, arg1, (arg2[9]), (arg3[9]));
  fiat_p1024_cmovznz_u64(&x11, arg1, (arg2[10]), (arg3[10]));
  fiat_p1024_cmovznz_u64(&x12, arg1, (arg2[11]), (arg3[11]));
  fiat_p1024_cmovznz_u64(&x13, arg1, (arg2[12]), (arg3[12]));
  fiat_p1024_cmovznz_u64(&x14, arg1, (arg2[13]), (arg3[13]));
  fiat_p1024_cmovznz_u64(&x15, arg1, (arg2[14]), (arg3[14]));
  fiat_p1024_cmovznz_u64(&x16, arg1, (arg2[15]), (arg3[15]));
  out1[0] = x1;
  out1[1] = x2;
  out1[2] = x3;
  out1[3] = x4;
  out1[4] = x5;
  out1[5] = x6;
  out1[6] = x7;
  out1[7] = x8;
  out1[8] = x9;
  out1[9] = x10;
  out1[10] = x11;
  out1[11] = x12;
  out1[12] = x13;
  out1[13] = x14;
  out1[14] = x15;
  out1[15] = x16;
}

/*
 * The function fiat_p1024_mulx_u64 is a multiplication, returning the full double-width result.
 *
 * Postconditions:
 *   out1 = (arg1 * arg2) mod 2^64
 *   out2 = ⌊arg1 * arg2 / 2^64⌋
 */
static inline void fiat_p1024_mulx_u64(uint64_t* restrict out1, uint64_t* restrict out2, const uint64_t arg1, const uint64_t arg2) {
	// TODO _mulx_u64 builtin, this function is equivalent to fiat_p512_mulx_u64
  const fiat_p1024_uint128 x1 = ((fiat_p1024_uint128)arg1 * arg2);
  *out1 = (uint64_t)(x1 & UINT64_C(0xffffffffffffffff));
  *out2 = (uint64_t)(x1 >> 64);
}

static inline void fiat_p1024_addcarryx_u64(uint64_t* out1, fiat_p1024_uint1* out2, fiat_p1024_uint1 arg1, uint64_t arg2, uint64_t arg3) {
  const fiat_p1024_uint128 x1 = ((arg1 + (fiat_p1024_uint128)arg2) + arg3);
  *out1 = (uint64_t)(x1 & UINT64_C(0xffffffffffffffff));
  *out2 = (fiat_p1024_uint1)(x1 >> 64);
}

static inline void fiat_p1024_subborrowx_u64(uint64_t* out1, fiat_p1024_uint1* out2, fiat_p1024_uint1 arg1, uint64_t arg2, uint64_t arg3) {
	// TODO _subborrow_u64, fiat_p512_subborrowx_u64
  const fiat_p1024_int128 x1 = ((arg2 - (fiat_p1024_int128)arg1) - arg3);
  const fiat_p1024_int1 x2 = (fiat_p1024_int1)(x1 >> 64);
  *out1 = (uint64_t)(x1 & UINT64_C(0xffffffffffffffff));
  *out2 = (fiat_p1024_uint1)(0x0 - x2);
}

void fiat_p1024_set_one(fiat_p1024_montgomery_domain_field_element out1);
void fiat_p1024_nonzero(uint64_t* out1, const uint64_t arg1[16]);

#endif /* fiat_p1024_H */
