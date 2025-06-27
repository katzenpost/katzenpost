#include <string.h>
#include <assert.h>

#include "csidh.h"
#include "primes.h"

// XXX: use affine initial P to save time in xMUL

static int validate_rec(proj *P, proj const *A, long long lower, long long upper, uintbig *order, int *criticaltestdone)
{
    proj Q;
    proj A24;
    xA24(&A24,A);

    assert(lower < upper);

    if (upper - lower == 1) {
      // now P is [(p+1) / l_lower] times the original random point
      if (fp_iszero(&P->z))
        return 0;

      if (*criticaltestdone != 1) {
        // is original point times p+1 the identity? test this via first l that we see
        xMUL_dac(&Q, &A24, 1, P, primes_dac[lower], primes_daclen[lower], primes_daclen[lower]);
        if (!fp_iszero(&Q.z))
          return -1;
        *criticaltestdone = 1;
      }

      uintbig_mul3_64(order, order, primes[lower]);

      uintbig tmp;
      if (uintbig_sub3(&tmp, &uintbig_four_sqrt_p, order))
        return 1;
      return 0;
    }

    long long mid = lower + (upper - lower + 1) / 2;

    Q = *P;
    for (long long i = lower; i < mid; ++i)
      xMUL_dac(&Q,&A24,1,&Q,primes_dac[i],primes_daclen[i],primes_daclen[i]);

    int result = validate_rec(&Q, A, mid, upper, order, criticaltestdone);
    if (result) return result;

    Q = *P;
    for (long long i = mid; i < upper; ++i)
      xMUL_dac(&Q,&A24,1,&Q,primes_dac[i],primes_daclen[i],primes_daclen[i]);

    return validate_rec(&Q, A, lower, mid, order, criticaltestdone);
}

int validate_cutofforder_v2(uintbig *order,const fp *P,const fp *A)
{
  const proj Aproj = {*A,fp_1};
  proj Pproj = {*P,fp_1};
  proj A24;
  int criticaltestdone = 0;

  xA24(&A24,&Aproj);

  /* maximal 2-power in p+1 */
  xDBL(&Pproj,&Pproj,&A24,1);
  xDBL(&Pproj,&Pproj,&A24,1);

  *order = uintbig_1;
  return validate_rec(&Pproj,&Aproj,0,primes_num,order,&criticaltestdone);
}

// output: true if key is valid
// output: false if key is invalid
bool validate(public_key const *in)
{
  uintbig tmp;
  if (!uintbig_sub3(&tmp,&in->A.x,&uintbig_p))
    return false; // A >= p, invalid

  fp tmp2 = fp_2;
  if (!memcmp(&in->A,&tmp2,sizeof(fp)))
    return false; // A = 2, invalid
  fp_add2(&tmp2,&in->A);
  if (fp_iszero(&tmp2))
    return false; // A = -2, invalid

  for (;;) {
    fp P;
    memset(&P, 0, sizeof(P));
    fp_random(&P);
    uintbig tmp;
    memset(&tmp, 0, sizeof(tmp));
    switch(validate_cutofforder_v2(&tmp,&P,&in->A)) {
      case 1: return true;
      case -1: return false;
    }
    // case 0: P didn't have big enough order to prove supersingularity
  }
}
