#ifndef FP_H
#define FP_H

#include "fp_namespace.h"
#include "uintbig.h"
#include "annotations.h"

#if HIGHCTIDH_PORTABLE == 1 || !(defined(__x86_64__) || defined(_M_X64))
/* we only have optimizations for amd64 so far, so on other platforms we
 * default to the portable code by defining HIGHCTIDH_PORTABLE:
 */
#ifndef HIGHCTIDH_PORTABLE
#define HIGHCTIDH_PORTABLE 1
#endif

#if 511 == BITS
#include "fiat_p511.h"
#elif 512 == BITS
#include "fiat_p512.h"
#elif 1024 == BITS
#include "fiat_p1024.h"
#elif 2048 == BITS
#include "fiat_p2048.h"
#else
#error "don't know which fiat_pBITS.h to include"
#endif /* 2048 != BITS */

/*
 * macro to turn FIAT_BITS(add) into fiat_p512_add, fiat_p1024_add, etc:
 */
#define FIAT_PASTER(x,y,z) x ## y ## _ ## z
#define FIAT_EVALUATOR(x,y, z) FIAT_PASTER(x,y, z)
#define FIAT_BITS(actual) FIAT_EVALUATOR(fiat_p, BITS, actual)
#endif /* end HIGHCTIDH_PORTABLE */

#ifndef FIAT_BITS
#define FIAT_BITS(actual) actual
#endif /* FIAT_BITS */

/* fp is in the Montgomery domain, so interpreting that
   as an integer should never make sense.
   enable compiler warnings when mixing up uintbig and fp. */
typedef struct fp {
    uintbig x;
} fp;

extern const fp fp_0;
extern const fp fp_1;
extern const fp fp_2;

void fp_cswap(fp *const x, fp *const y, long long c); /* c is 0 or 1 */
void __attribute__((nonnull))
fp_cmov(fp *x, const fp *y, long long c); /* c is 0 or 1 */

void fp_add2(fp *const x, fp const *const y);
void fp_sub2(fp *const x, fp const *const y);
void
__attribute__((nonnull))
//__attribute__ ((access(read_only,2)))
fp_mul2(fp *const x, fp const *const y);

void ATTR_INITIALIZE_1st
__attribute__((nonnull))
__attribute__((flatten))
fp_add3(fp *const x, fp const *const y, fp const *const z);
void ATTR_INITIALIZE_1st
__attribute__((nonnull))
__attribute__((flatten))
fp_sub3(fp *const x, fp const *const y, fp const *const z);

/*
void ATTR_INITIALIZE_1st
__attribute__((nonnull))
__attribute__((flatten))
fp_mul3(fp *const x, fp const *const y, fp const *const z)
	__attribute__ ((alias ("fiat_p512_mul")));
*/
//void fp_mul3 () __attribute__ ((weak, alias ("fiat_p512_mul")));
#if HIGHCTIDH_PORTABLE == 1
#define highctidh_511_fp_mul3(a,b,c) FIAT_BITS(mul)((uint64_t *)a,(const uint64_t*)b,(const uint64_t*)c)
#define highctidh_512_fp_mul3(a,b,c) FIAT_BITS(mul)((uint64_t *)a,(const uint64_t*)b,(const uint64_t*)c)
#define highctidh_1024_fp_mul3(a,b,c) FIAT_BITS(mul)((uint64_t *)a,(const uint64_t*)b,(const uint64_t*)c)
#define highctidh_2048_fp_mul3(a,b,c) FIAT_BITS(mul)((uint64_t *)a,(const uint64_t*)b,(const uint64_t*)c)
#endif

#if HIGHCTIDH_PORTABLE == 0
void fp_mul3(fp *const a, const fp *const b, const fp *const c);
#endif /* ndef HIGHCTIDH_PORTABLE */

void fp_sq1(fp *x);
void fp_sq2(fp *const x, fp const *const y);

extern long long fp_mulsq_count;
extern long long fp_sq_count;
extern long long fp_addsub_count;

static inline void fp_sq1_rep(fp *const x,long long n)
{
  while (n > 0) {
    --n;
    fp_sq1(x);
  }
}

static inline void fp_neg1(fp *const x)
{
  fp_sub3(x,&fp_0,x);
}

/*
 * a := 0 - b
 */
static inline
__attribute__((nonnull))
void fp_neg2(fp *const x,const fp *const y)
{
#if HIGHCTIDH_PORTABLE == 1
	FIAT_BITS(opp)(x->x.c, y->x.c);
#else
	fp_sub3(x, &fp_0, y);
#endif
}

static inline void fp_double1(fp *const x)
{
  fp_add2(x,x);
}

static inline void fp_double2(fp *const x,const fp *const y)
{
  fp_add3(x,y,y);
}

static inline void fp_quadruple2(fp *const x,const fp *const y)
{
  fp_double2(x,y);
  fp_double1(x);
}

static inline void fp_quadruple1(fp *const x)
{
  fp_double1(x);
  fp_double1(x);
}

static inline long long fp_iszero(const fp *const x)
{
  return uintbig_iszero(&x->x);
}

static inline long long fp_isequal(const fp *const x,const fp *const y)
{
  return uintbig_isequal(&x->x,&y->x);
}

void fp_inv(fp *const x);

// if x is a square: replace x by principal sqrt and return 1
// else: return 0
long long fp_sqrt(fp *const x);

#include "randombytes.h"
#include "crypto_declassify.h"

static inline void fp_random(fp *const x)
{
  for (;;) {
    randombytes(x,sizeof(fp));

    uintbig diff;
    long long accept = uintbig_sub3(&diff,&x->x,&uintbig_p);

    crypto_declassify(&accept,sizeof accept);
    if (accept) return;
  }
}

#endif
