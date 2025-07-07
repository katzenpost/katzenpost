/*
 * skeleton for expressing fp*.S in terms of fiat-crypto
 */
#include <stdint.h>
#include <assert.h>
#include <string.h>


#include "uintbig_namespace.h"
#include "fp.h"
#include "annotations.h"

#if HIGHCTIDH_PORTABLE == 0 && (defined(__x86_64__) || defined(__i86pc__))
#define highctidh_macro_stringize(x) #x
#define highctidh_macro_str(y) highctidh_macro_stringize(y)
__asm__ (".include \"uintbig" highctidh_macro_str(BITS)  ".S\"");
__asm__ (".include \"fp" highctidh_macro_str(BITS) ".S\"");

#else
#if defined(CGONUTS)
#define DONTMINDIFIDO
#endif
/*
 * The definitions in this unit are only needed when they are not provided
 * by the optimizied assembly units.
 */

/*
 * These are replacements for uintbig512.S:
 */
#if 511 == BITS || 512 == BITS
const uintbig uintbig_1 = {.c = {1,0}};
const uintbig uintbig_p = {.c = {
		0x1b81b90533c6c87bU, 0xc2721bf457aca835U,
		0x516730cc1f0b4f25U, 0xa7aac6c567f35507U,
		0x5afbfcc69322c9cdU, 0xb42d083aedc88c42U,
		0xfc8ab0d15e3e4c4aU, 0x65b48e8f740f89bfU}};
const uintbig uintbig_four_sqrt_p = {.c={
		0x17895e71e1a20b3fU, 0x38d0cd95f8636a56U,
		0x142b9541e59682cdU, 0x856f1399d91d6592U,
		2, 0, 0, 0
	}}; /* TODO lifted from uintbig512.S, how is this calculated?
	     * might need to expose to/from_montgomery for the calculations.
	     * or just copy from the relevant uintbig*.S for each field size.
	     */
_Static_assert(sizeof(uintbig) == 64, "uintbig must be 64 bytes for p512");
const fp fp_1 = {{{0xc8fc8df598726f0aU, 0x7b1bc81750a6af95U, 0x5d319e67c1e961b4U, 0xb0aa7275301955f1U, 0x4a080672d9ba6c64U, 0x97a5ef8a246ee77bU, 0x6ea9e5d4383676aU, 0x3496e2e117e0ec80U}}};
const fp fp_2 = {{{0x767762e5fd1e1599U, 0x33c5743a49a0b6f6U, 0x68fc0c0364c77443U, 0xb9aa1e24f83f56dbU, 0x3914101f20520efbU, 0x7b1ed6d95b1542b4U, 0x114a8be928c8828aU, 0x3793732bbb24f40U}}};
#endif /* 511 == BITS || 512 == BITSy */

#if 1024 == BITS
const uintbig highctidh_1024_uintbig_1 = {.c = {1,0}};
const uintbig highctidh_1024_uintbig_p = {.c = {
		0xdbe34c5460e36453U, 0xa1d81eebbc3d344dU, 0x514ba72cb8d89fd3U,
		0xc2cab6a0e287f1bd, 0x642aca4d5a313709U, 0x6b317c5431541f40U,
		0xb97c56d1de81ede5U, 0x0978dbeed90a2b58, 0x7611ad4f90441c80U,
		0xf811d9c419ec8329U, 0x4d6c594a8ad82d2dU, 0xf06de2471cf9386e,
		0x0683cf25db31ad5bU, 0x216c22bc86f21a08U, 0xd89dec879007ebd7U,
		0x0ece55ed427012a9U
	}};

const uintbig highctidh_1024_uintbig_four_sqrt_p = {.c = {
		0xeba75c5815bb0d57U, 0xfec8564a9ae457c6U, 0xe362e1c2334bd738U,
		0x56f74a246ef0a30eU, 0x4a598c9571aeb858U, 0xc5617b211ccad355U,
		0x4fb69e4928ccc442U, 0xf643475c7915859c,
		0,0,0,0,
		0,0,0,0
	}};
_Static_assert(sizeof(uintbig) == 128, "uintbig must be 128 bytes for p1024");
const fp fp_1 = {{{0x65e7ee6590e6567dU, 0x40a5f2587fef86d4U, 0x99f9e607b99d62f2U, 0x1089df50f4f8f26dU, 0x592890dd02bb585aU, 0xe1b6be68b969ecb9U, 0xaebe3c10395f33c3U, 0x5ef9652396531f1bU, 0x28d37db76b7a1b7fU, 0x86d089fa474b4a3fU, 0xdbce120cc7a4fff2U, 0x8b3f947137340acU, 0x913f3e7c71b37ce5U, 0xc7d1b17b09ec4577U, 0x9d834aff6f7956b6U, 0x44c4b3e968ec2b8U}}};
const fp fp_2 = {{{0xcbcfdccb21ccacfaU, 0x814be4b0ffdf0da8U, 0x33f3cc0f733ac5e4U, 0x2113bea1e9f1e4dbU, 0xb25121ba0576b0b4U, 0xc36d7cd172d3d972U, 0x5d7c782072be6787U, 0xbdf2ca472ca63e37U, 0x51a6fb6ed6f436feU, 0xda113f48e96947eU, 0xb79c24198f49ffe5U, 0x1167f28e26e68159U, 0x227e7cf8e366f9caU, 0x8fa362f613d88aefU, 0x3b0695fedef2ad6dU, 0x898967d2d1d8571U}}};
#endif /* 1024 == BITS */

#if 2048 == BITS
const uintbig highctidh_2048_uintbig_1 = {.c = {1,0}};
const uintbig highctidh_2048_uintbig_p = {.c = {
		0x7790d615ea034943U, 0xdc703f0cd8c4d918U, 0x95a98036c813c788U, 0xe111b0d22ab8ecaaU,
		0x6478407d7a9a56eeU, 0xa7bec86fabaf787fU, 0x44454e851cf305abU, 0x44084e1a73c76cb2U,
		0x2842bbe4dbacc65eU, 0x58e89497ef35bbb9U, 0x9796620b3ad8a5d4U, 0x5377d53e856cc9a3U,
		0x7c4cb419996f45e7U, 0x88c691b2d452a8acU, 0x0da1783672767abbU, 0x9844e5c09baf59ecU,
		0xe33586d1208a1017U, 0x7d84f102b5fde2eaU, 0x30d2edfe50198c64U, 0x095ac8a9f3ce2b0cU,
		0x93e73abd17e3aa46U, 0xc680497933375253U, 0x6557ebe96d91aeddU, 0x4dd6024bf2f8feabU,
		0xb8523d6a302abf28U, 0x33a8779a1ec8b8c2U, 0x584eb12932f72abbU, 0xdbd1fc2133770253U,
		0xddffdcf1aee53f12U, 0x4d8854e8b3e19c53U, 0x97fefc90e8196ed9U, 0x438efcab10254c64
	}};
const uintbig highctidh_2048_uintbig_four_sqrt_p = {.c = {
		0x713138678208efe5U, 0x99b865c7a60b9d15U, 0xcb9d5709a6d520ecU, 0x8ba25da98b117e65U,
   0xb53f431fbbbc1b57U, 0xa182b3a2a32514caU, 0xbd8509d767f7a86cU, 0x50d56ce140ad8057U,
    0xf15c586b92287b69U, 0x89a81119287fc51fU, 0x5721ecd10a5f822aU, 0xbc1272d7e7a1d02cU,
    0x8ae8830a4b03c676U, 0xb4c29be61adeea3aU, 0xd31c1b050625e30bU, 0x0e0aa7f8149f0a5aU, 0U
	}};
_Static_assert(sizeof(uintbig) == 256, "uintbig must be 256 bytes for p2048");
const fp fp_1 = {{{0x994d7dbe41f62437U, 0x6aaf42d975b174b6U, 0x3f037f5ba7c4a965U, 0x5ccaed897fd53a00U, 0xd2973e879030fb33U, 0x8c3a6b0fcf19681U, 0x33301470a926eefdU, 0x33e715b0a4a9b9e9U, 0x8737cc516cf9ace5U, 0xf5464238325eccd4U, 0x393cd9de4f760e82U, 0x59880446fb9a315U, 0x8b19e3b333b22e4aU, 0x65ac4ae7830805faU, 0xd71b975ca89c8fcdU, 0x37314ebe2cf1f23bU, 0x565f6b8c9e61cfb9U, 0x87712cf7de06573fU, 0x6d8736050fb35ad2U, 0xe3efa60224957edbU, 0x444a4fc8b855012dU, 0xac7f2394665a0905U, 0xcff83c43b74af366U, 0x167df91c271503fdU, 0xd70947c16f7fc287U, 0x65069931a3a5d5b7U, 0xf713ec84671a7fceU, 0x6c8a0b9c659af905U, 0x6600692af35042c7U, 0x17670145e45b2b04U, 0x38030a4d47b3b374U, 0x355309fecf901ad2U}}};
const fp fp_2 = {{{0xbb0a256699e8ff2bU, 0xf8ee46a6129e1054U, 0xe85d7e8087758b41U, 0xd8842a40d4f18755U, 0x40b63c91a5c79f77U, 0x69c884f24e33b484U, 0x221ada5c355ad84eU, 0x23c5dd46d58c0720U, 0xe62cdcbdfe46936cU, 0x91a3efd87587ddefU, 0xdae351b164137731U, 0xb7b92b4a5a067c86U, 0x99e7134ccdf516acU, 0x4292041c31bd6348U, 0xa095b682dec2a4dfU, 0xd61db7bbbe348a8bU, 0xc98950481c398f5aU, 0x915d68ed060ecb93U, 0xaa3b7e0bcf4d2940U, 0xbe84835a555cd2aaU, 0xf4ad64d458c65815U, 0x927dfdaf997cbfb6U, 0x3a988c9e010437efU, 0xdf25efec5b310950U, 0xf5c05218aed4c5e5U, 0x9664bac92882f2acU, 0x95d927df9b3dd4e1U, 0xfd421b1797beefb8U, 0xee00f56437bb467bU, 0xe145ada314d4b9b4U, 0xd8071809a74df80eU, 0x271717528efae93fU}}};

#elif !defined(uintbig_p) // 2048 != BITS

#error "unknown field size not p512 || p1024 || p2048"

#endif /* 2048 != BITS && !defined(uintbig_p) */


/*
 * regular multi-limb multiplication
 * x := y[i] * z
 */
void
__attribute__((flatten))
uintbig_mul3_64(uintbig *const x, uintbig const *const y, const uint64_t z)
{
	uint64_t carry_r10 = 0;
	uint64_t carry_r11 = 0;

	FIAT_BITS(mulx_u64)(&x->c[0], &carry_r10, y->c[0], z);
	// mulx carry, x->c[0], y->c[0] ; z=rdx implicit
	// mulx   r10,     rax, [rsi+0]
	// mov [rdi+0],    rax

	FIAT_BITS(mulx_u64)(&x->c[1], &carry_r11, y->c[1], z);
	// mulx r11, rax, [rsi + 8]
	FIAT_BITS(uint1) cf = !!(x->c[1] + carry_r10 < x->c[1]);
	// set CF on overflow (carry)

	// TODO does carry_r10 need to be sign-extended?
	x->c[1] += carry_r10;
	// add rax, r10,
	// mov [rdi + 8], rax
#ifdef __gcc__
#pragma GCC push_options
#pragma GCC unroll(100)
#else
#ifdef __clang__
#pragma unroll(100)
#endif
#endif

	for (size_t idx = 2; idx < sizeof(x->c)/sizeof(x->c[0]); idx+=2) {
	FIAT_BITS(mulx_u64)(&x->c[idx], &carry_r10, y->c[idx], z);
	// mulx r10, rax, [rsi + 16]
	FIAT_BITS(addcarryx_u64)(&x->c[idx], &cf, cf, x->c[idx], carry_r11);
	// assert(cf == 0 || cf == 1); cf = !!cf; // TODO: add a test that fails without this.
	// adcx rax, r11
	// mov [rdi + 16], rax

	FIAT_BITS(mulx_u64)(&x->c[idx+1], &carry_r11, y->c[idx+1], z);
	// mulx r11, rax, [rsi + 24]
	FIAT_BITS(addcarryx_u64)(&x->c[idx+1], &cf, cf, x->c[idx+1], carry_r10);
	// assert(cf == 0 || cf == 1); cf = !!cf;
	// adcx rax, r10
	// mov [rdi + 24], rax
	}
#ifdef __gcc__
	#pragma GCC pop_options
#endif
}

/*
 * 1 when the bit at (bitoffset) of x is set
 * 0 when the bit at (bitoffset) of x is not set
 * ie this, but accounting for limbs:
 * x & (1 << (511 - offset))
 */
// int64_t // TODO
long long
uintbig_bit(uintbig const *x, uint64_t bitoffset)
{
	assert(sizeof(x->c)*8 > bitoffset); // bounds check
	_Static_assert(sizeof(x->c[0]) == 64/8, "element size");

	// TODO not tested, but implemented naively from interpreting
	// the assembly code:
	return 1 & (x->c[bitoffset / 64] >> (bitoffset % 64));

	// TODO: note that neither the assembly function nor this
	// implementation is constant-time and might leak the (bitoffset)
	// function parameter through timing analysis.

	/* test:
	 *   initialize to 0 such that uintbig_iszero(x),
	 *   pick a random offset,
	 *   uintbig_setbit(x, offset),
	 *   test that uintbig_bit(x, offset) == 1
	 *   test that uintbig_bit(x, not_offset) == 0
	 */

	/*
	 * test:
	 *   x := initialize to random,
	 *   x_old := x
	 *   pick a random offset
	 *   old = uintbig_bit(x, offset)
	 *   uintbig_setbit(x, offset)
	 *   if old:
	 *     uintbig_isequal(x, x_old))
	 *   if not old:
	 *     !uintbig_isequal(x, x_old))
	 *     1 == popcount(x) - popcount(x_old) // differ by one bit
	 *     for idx in 0..511:
	 *        uintbig_bit(x, idx) == uintbig(x_old, idx) unless idx == random offset
	 */
}

/*
 * set the lower 64bits of x to (newlow) and clear the remaining higher bits.
 */
void
uintbig_set(uintbig *const x, uint64_t newlow)
{
	memset(x->c, 0, sizeof(x->c));
	x->c[0] = newlow;
	/*
	for (size_t i = 1; i < sizeof(x->c)/sizeof(x->c[0]); i++) {
		x->c[i] ^= x->c[i]; // x[i] = 0
		}*/
}


/*
 * sets the bit of (x) at (bitoffset) such that
 * uintbig_bit(x,bitoffset) == 1
 */
void
uintbig_setbit(uintbig *const x, const uint64_t bitoffset)
{
	assert(sizeof(x->c)*8 > bitoffset); // bounds check
	_Static_assert(sizeof(x->c[0]) == 64/8, "element not 64 bits long");
	// TODO not tested
	x->c[bitoffset / 64] |= (1 << (bitoffset % 64));
	assert(uintbig_bit(x, bitoffset) == 1);
}

/*
 * x := y + z
 * return 0 if no overflow (no carry)
 * return 1 if overflow (carry)
 * NOTE: apart from test.c this is only used in fp512.S
 */
long long // int64_t
ATTR_INITIALIZE_1st
uintbig_add3(uintbig *x, uintbig const *y, uintbig const *z)
{
	_Static_assert(sizeof(x->c) == sizeof(
		    FIAT_BITS(non_montgomery_domain_field_element)), "el_sz");

	FIAT_BITS(uint1) carry = 0;
	for (size_t limb = 0; limb < sizeof(x->c)/sizeof(x->c[0]); limb++)
	{
		FIAT_BITS(addcarryx_u64)(
			/* output: */
			&x->c[limb],
			    &carry, /* carry (max) one bit over from addition */
			    /* input: */
			carry, y->c[limb], z->c[limb]);
	}
	return carry;
	/*
	 * test:
	 * pick random y,z
	 * carry := uintbig_add3(x, y,z)
	 * if carry:
	 *   // y+z > 2^512
	 *   y[7] | z[7] > (1<<62) // union of last limbs must be large?
	 *   y[7] + z[7] + 1 < (-1ULL) // sum of last limbs +1 must overflow
	 * if not carry:
	 *   // y+z < 2^512
	 *   y[7] | z[7] < (1<<62) // union of last limbs must be small
	 */
}

/*
 * x := y - z
 * returns 0 if no underflow (no borrow)
 * returns 1 if overflow (borrow)
 */
long long // TODO int64_t
ATTR_INITIALIZE_1st
uintbig_sub3(uintbig *x, uintbig const *const y, uintbig const *const z)
{
	// like uintbig_add3, but using
	// fiat_p512_subborrowx_u64 instead of fiat_p512_addcarryx_u64
	_Static_assert(sizeof(*x) == sizeof(
		    FIAT_BITS(non_montgomery_domain_field_element)), "sub3 fe size");
	FIAT_BITS(uint1) carry = 0;
	for (size_t limb = 0; limb < sizeof(x->c)/sizeof(x->c[0]); limb++)
	{
		FIAT_BITS(subborrowx_u64)(
			/* output: */
			&x->c[limb], &carry,
			/* input: */
			carry, y->c[limb], z->c[limb]);
	}
	return carry;
	/*
	 * test:
	 *   pick random y,z
	 *   borrow := uintbig_sub3(x,y,z)
	 *   carry := uintbig_add3(y1, x, z)
	 *   if borrow:
	 *     !uintbig_isequal(y1, y) // we should have lost information
	 *   if not borrow:
	 *     carry == 0 // adding it back shouldn't overflow if subtracting didn't underflow
	 *     uintbig_isequal(y1, y)
	 */
}


/*
 * TODO: these are defined in fp512.S etc.
 * we can either hardcode them or populate them using a constructor function
 */
const fp fp_0 = {{{0}}};

/*
 * Operation counters
 */
long long fp_mulsq_count = 0;
long long fp_sq_count = 0;
long long fp_addsub_count = 0;

// debug macro to dump out a fp:
#include <stdio.h>
#define dump_fp(fp2) {for (size_t i=0; i<sizeof(fp2.x.c)/sizeof(fp2.x.c[0]);i++) { printf("%#lxU, ", fp2.x.c[i]); };printf("\n"); }

//  /*
//   * Constructor function to initialize fp0, fp1, fp2 at program start.
//   */
//  #include <stdio.h>
//  static void
//  #if 0
//  __attribute__((constructor (0)))
//  #else
//  __attribute__((unused))
//  #endif /* constructor */
//  constructor(void)
//  {
//      fp fp0 = {0};
//      fp fp1 = {0};
//      fp fp2 = {0};
//      FIAT_BITS(set_one)((uint64_t *)&fp1.x.c); // fp1 := 1
//      fp_add3(&fp2, &fp1, &fp1); // fp2 := fp1 + fp1
//      // TODO: we either need to hardcode these for each p512, p1024, p2048,
//      // or alternatively we can use this function to dump out the constants.
//      //dump_fp(fp1);
//      //dump_fp(fp2);
//      assert(0 == memcmp(fp0.x.c, fp_0.x.c, sizeof(fp0.x.c)));
//      assert(0 == memcmp(fp1.x.c, fp_1.x.c, sizeof(fp1.x.c)));
//      assert(0 == memcmp(fp2.x.c, fp_2.x.c, sizeof(fp2.x.c)));
//  }

void
fp_copy(fp *a, fp *b)
{
	/* TODO not sure if this is used at all? should probably test that it works anyhow. */
	*a = *b;
}

/*
 * condition = 0 -> a := a
 * condition = 1 -> a := b
 */
void
fp_cmov(fp *const a, const fp *const b, const long long condition)
{
	/*
	 * note that it's safe to use (a) as both input and output
	 * since fiat-crypto always defers writing to outputs until
	 * the end of the function:
	 */
	FIAT_BITS(selectznz)(a->x.c, condition, a->x.c, b->x.c);
}

/*
 * condition = 0 -> a,b := a,b
 * condition = 1 -> a,b := b,a
 */
void
__attribute__((nonnull))
fp_cswap(fp *const restrict a, fp *const restrict b, long long condition)
{
	const fp old_a = *a;

	/*
	 * fiat-crypto expects exactly 0 or 1 for "not zero":
	 */
	condition = !!condition;

	FIAT_BITS(selectznz)(a->x.c, condition, a->x.c, b->x.c);
	FIAT_BITS(selectznz)(b->x.c, condition, b->x.c,  (const uint64_t *)&old_a.x.c);
}

/*
 * x := x + z
 */
void
__attribute__((nonnull))
fp_add2(fp *const x, const fp *const z)
{
	fp_add3(x, x, z);
}

/*
 * x := y + z
 */
void ATTR_INITIALIZE_1st
__attribute__((nonnull))
//__attribute__ ((access(read_only,2)))
fp_add3(fp *const x, fp const *y, fp const *z)
{
	fp_addsub_count += 1;
	FIAT_BITS(add)(x->x.c, y->x.c, z->x.c);
}

/*
 * x := x - z
 */
void
__attribute__((nonnull))
fp_sub2(fp *const x, const fp *const z)
{
	fp_sub3(x, x, z);
	/*
	 * test:
	 *   pick x,y
	 *   fp_sub3(t, x, y) // t := x-y
	 *   fp_add2(t, y)    // t := x-y+y
	 *   fp_isequal(t,x)  // === x
	 *
	 * test:
	 *   pick x
	 *   t := fp0
	 *   fp_sub2(t, x)     // t := 0-x
	 *   fp_neg2(t2, x)    // t2 := -x
	 *   fp_isequal(t, t2) // t === t2
	 *   fp_add3(t3, t, x)   // t3 := 0-x+x
	 *   fp_isequal(t3, fp0) // === 0
	 */
}

/*
 * x := y - z
 */
void
__attribute__((nonnull))
ATTR_INITIALIZE_1st
fp_sub3(fp *const x, const fp *const y, const fp *const z)
{
	fp_addsub_count += 1;
	FIAT_BITS(sub)(x->x.c, y->x.c, z->x.c);
}

/*
 * x := x * z
 */
void
__attribute__((nonnull))
//__attribute__ ((access(read_only,2)))
fp_mul2(fp *const x, fp const *z) {
	fp_mul3(x, x, z);
}

/*
 * x := x^2
 */
void
__attribute__((nonnull))
__attribute__((flatten))
fp_sq1(fp *const x) {
	fp_sq2(x, x);
}

/*
 * x := y^2
 */
void ATTR_INITIALIZE_1st
__attribute__((nonnull))
__attribute__((flatten))
//__attribute__ ((access(read_only,2)))
fp_sq2(fp *const x, fp const *const y)
{
	fp_sq_count += 1;
	FIAT_BITS(square)(x->x.c, y->x.c);
}

#endif /* HIGHCTIDH_PORTABLE */
