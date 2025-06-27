#ifndef fiat_p512_H
#define fiat_p512_H
#include <stdint.h>
typedef unsigned char fiat_p512_uint1;
typedef signed char fiat_p512_int1;
typedef uint64_t fiat_p512_montgomery_domain_field_element[8];
typedef uint64_t fiat_p512_non_montgomery_domain_field_element[8];

#if defined(__GNUC__) || defined(__clang__)
#  define FIAT_P512_FIAT_EXTENSION __extension__
#  define FIAT_P512_FIAT_INLINE __inline__
#else
#  define FIAT_P512_FIAT_EXTENSION
#  define FIAT_P512_FIAT_INLINE
#endif

FIAT_P512_FIAT_EXTENSION typedef signed __int128 fiat_p512_int128;
FIAT_P512_FIAT_EXTENSION typedef unsigned __int128 fiat_p512_uint128;


void fiat_p512_mul(fiat_p512_montgomery_domain_field_element out1, const fiat_p512_montgomery_domain_field_element arg1, const fiat_p512_montgomery_domain_field_element arg2);
void fiat_p512_square(fiat_p512_montgomery_domain_field_element out1, const fiat_p512_montgomery_domain_field_element arg1);
void fiat_p512_add(fiat_p512_montgomery_domain_field_element out1, const fiat_p512_montgomery_domain_field_element arg1, const fiat_p512_montgomery_domain_field_element arg2);
void fiat_p512_sub(fiat_p512_montgomery_domain_field_element out1, const fiat_p512_montgomery_domain_field_element arg1, const fiat_p512_montgomery_domain_field_element arg2);
void fiat_p512_opp(fiat_p512_montgomery_domain_field_element out1, const fiat_p512_montgomery_domain_field_element arg1);

static inline void fiat_p512_selectznz(uint64_t out1[8], const fiat_p512_uint1 arg1, const uint64_t arg2[8], const uint64_t arg3[8]) {
  register const uint64_t pick_z = (fiat_p512_int1)(0x0 - ((!arg1)));
  register const uint64_t pick_nz = ~pick_z;

  out1[0] = (pick_z & arg2[0]) | ((pick_nz) & arg3[0]);
  out1[1] = (pick_z & arg2[1]) | ((pick_nz) & arg3[1]);
  out1[2] = (pick_z & arg2[2]) | ((pick_nz) & arg3[2]);
  out1[3] = (pick_z & arg2[3]) | ((pick_nz) & arg3[3]);
  out1[4] = (pick_z & arg2[4]) | ((pick_nz) & arg3[4]);
  out1[5] = (pick_z & arg2[5]) | ((pick_nz) & arg3[5]);
  out1[6] = (pick_z & arg2[6]) | ((pick_nz) & arg3[6]);
  out1[7] = (pick_z & arg2[7]) | ((pick_nz) & arg3[7]);
}

//#include <immintrin.h>
//#include <x86intrin.h>

static inline void fiat_p512_mulx_u64(uint64_t* restrict out1, uint64_t* restrict out2, const uint64_t arg1, const uint64_t arg2) {
  // *out1 = _mulx_u64(arg1,arg2,(long long unsigned int*)out2)
  // mulx out2, out1, arg1   (rdx = arg2)
  const fiat_p512_uint128 x1 = ((fiat_p512_uint128)arg1 * arg2);
  *out1 = (uint64_t)(x1 & UINT64_C(0xffffffffffffffff));
  *out2 = (uint64_t)(x1 >> 64);
}
static inline void fiat_p512_addcarryx_u64(uint64_t* restrict out1, fiat_p512_uint1* restrict out2, const fiat_p512_uint1 arg1, const uint64_t arg2, const uint64_t arg3) {
#if defined _addcarry_u64
  *out2 = _addcarry_u64(arg1, arg2, arg3, out1);
#else
  // arg1 -> cf
  // arg3 -> rdx
  //   adcx (r:arg2,w:out1), arg1
  // out2 <- cf
  const fiat_p512_uint128 x1 = ((arg1 + (fiat_p512_uint128)arg2) + arg3);
  *out1 = (uint64_t)(x1 & UINT64_C(0xffffffffffffffff));
  *out2 = (fiat_p512_uint1)(x1 >> 64);
#endif
}

static inline void fiat_p512_subborrowx_u64(uint64_t* restrict out1, fiat_p512_uint1* restrict out2, const fiat_p512_uint1 arg1, const uint64_t arg2, const uint64_t arg3) {
#if defined _subborrow_u64
  *out2 = _subborrow_u64(arg1,arg2,arg3,(long long unsigned int*)out1)
#else
  const fiat_p512_int128 x1 = ((arg2 - (fiat_p512_int128)arg1) - arg3);
  const fiat_p512_int1 x2 = (fiat_p512_int1)(x1 >> 64);
  *out1 = (uint64_t)(x1 & UINT64_C(0xffffffffffffffff));
  *out2 = (fiat_p512_uint1)(0x0 - x2);
#endif
}

void fiat_p512_set_one(fiat_p512_montgomery_domain_field_element out1);
void fiat_p512_nonzero(uint64_t* out1, const uint64_t arg1[8]);

#endif /* fiat_p512_H */
