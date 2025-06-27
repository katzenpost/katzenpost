#include <string.h>
#include <assert.h>

#include "naidne.h"
#include "csidh.h"
#include "fp.h"
#include "primes.h"
#include "int64mask.h"
#include "elligator.h"
#include "random.h"
#include "crypto_declassify.h"

const public_key base = {0}; /* A = 0 */

/*
 * Initialize a public_key from a byte array, byteswapping for
 * big-endian portability.
 */
void
public_key_from_bytes(public_key *const pk, const char *const input)
{
	uint64_t *input_u64 = (uint64_t *)input;
	for(size_t i=0; i < sizeof(pk->A.x.c)/sizeof(pk->A.x.c[0]); i++){
    // We could write this as so on GNU/Linux, BSD, and MacOS
		// pk->A.x.c[i] = le64toh(*input_u64++);
    // however on Solaris 11.4 sparcv9 64bit it throws a hard error of
    // 'multiple unsequenced modifications'
		pk->A.x.c[i] = le64toh(*input_u64);
    input_u64++;
	}
}

void
public_key_to_bytes(char *const output, const public_key *const pk)
{
	uint64_t *output_u64 = (uint64_t *)output;
	for(size_t i=0; i < sizeof(pk->A.x.c)/sizeof(pk->A.x.c[0]); i++){
		*output_u64++ = htole64(pk->A.x.c[i]);
	}
}

static void clearpublicprimes(proj *P,const proj *A24,int outsideblock[primes_batches])
{
  // clear powers of 2
  xDBL(P,P,A24,0);
  xDBL(P,P,A24,0);

  // clear primes outside all batches
  for (int64_t j = primes_batchstop[primes_batches-1];j < primes_num;++j)
    xMUL_dac(P,A24,0,P,primes_dac[j],primes_daclen[j],primes_daclen[j]);

  // clear primes in the batches outside this block
  for (int64_t i = 0;i < primes_batches;++i)
    if (outsideblock[i])
      for (int64_t j = primes_batchstart[i];j < primes_batchstop[i];++j)
        xMUL_dac(P,A24,0,P,primes_dac[j],primes_daclen[j],primes_daclen[j]);
}

long long csidh_stattried[primes_batches];
long long csidh_statsucceeded[primes_batches];

/* goal: constant time */
void action(public_key *out, public_key const *in, private_key const *priv)
{
  proj A = {in->A,fp_1};
  proj A24;
  xA24(&A24,&A);

  int64_t batchtodo[primes_batches];
  int64_t batchtodosum = 0;
  for (int64_t i = 0;i < primes_batches;++i)
    batchtodosum += batchtodo[i] = primes_batchbound[i];

  int64_t todonegativemask[primes_num]; // -1 for negative exponent, else 0
  int64_t todo[primes_num]; // absolute value of exponent
  for (int64_t i = 0;i < primes_num;++i) {
    int64_t ei = priv->e[i];
    todonegativemask[i] = int64mask_negative(ei);
    ei ^= todonegativemask[i]&(ei^-ei);
    todo[i] = ei;
  }

  while (batchtodosum > 0) {
    // each target is a batch with batchtodo>0

    int64_t target[primes_batches];
    int64_t targetstart[primes_batches];
    int64_t targetstop[primes_batches];
    int64_t targetmaxdaclen[primes_batches];
    int64_t targetlen = 0;

    for (int64_t b = 0;b < primes_batches;++b)
      if (batchtodo[b])
        target[targetlen++] = b;

    // trying to optimize order of targets
    if (targetlen > 3) {
      for (int64_t i = 0;i < targetlen-2;++i) {
        int64_t j = targetlen-3-i;
        if (i < j) {
          int64_t b = target[i];
          target[i] = target[j];
          target[j] = b;
        }
      }
      // order now looks like 5 4 3 2 1 0 6 7

      int64_t b = target[0];
      target[0] = target[targetlen-2];
      target[targetlen-2] = b;
      // order now looks like 6 4 3 2 1 0 5 7
    }

    for (int64_t i = 0;i < targetlen;++i)
      for (int64_t j = i+1;j < targetlen;++j)
        assert(target[i] != target[j]);

    for (int64_t i = 0;i < targetlen;++i) {
      int64_t b = target[i];
      targetstart[i] = primes_batchstart[b];
      targetstop[i] = primes_batchstop[b];
      targetmaxdaclen[i] = primes_batchmaxdaclen[b];
    }

    int64_t targetmask[primes_batches];
    int64_t targetindex[primes_batches];
    int64_t targetprime[primes_batches];
    int64_t targetnegative[primes_batches];
    int64_t targetdac[primes_batches];
    int64_t targetdaclen[primes_batches];

    // goal for
    // targetmask[i],targetindex[i],targetprime[i],targetnegative[i]:
    // 0,primes[targetstart[i]],1,0 if all todo[j] in target i are 0
    // -1,j,primes[j],0 if first nonzero todo[j] is positive
    // -1,j,primes[j],-1 if first nonzero todo[j] is negative

    for (int64_t i = 0;i < targetlen;++i) {
      targetmask[i] = 0;
      targetindex[i] = targetstart[i];
      targetprime[i] = primes[targetstart[i]];
      targetdac[i] = primes_dac[targetstart[i]];
      targetdaclen[i] = primes_daclen[targetstart[i]];
      targetnegative[i] = 0;
      for (int64_t j = targetstart[i];j < targetstop[i];++j) {
        int64_t updatemask = int64mask_nonzero(todo[j]);
        updatemask &= ~targetmask[i];
        targetnegative[i] ^= updatemask&todonegativemask[j];
        targetindex[i] ^= updatemask&(targetindex[i]^j);
        targetprime[i] ^= updatemask&(targetprime[i]^primes[j]);
        targetdac[i] ^= updatemask&(targetdac[i]^primes_dac[j]);
        targetdaclen[i] ^= updatemask&(targetdaclen[i]^primes_daclen[j]);
        targetmask[i] ^= updatemask;
      }
    }

    int64_t shuffleprimedac[primes_num];
    int64_t shuffleprimedaclen[primes_num];
    // shuffle means: selected prime is at beginning of each batch
    for (int64_t i = 0;i < targetlen;++i) {
      for (int64_t j = targetstart[i]+1;j < targetstop[i];++j) {
        int64_t moveright = ~int64mask_negative(targetindex[i]-j);
        shuffleprimedac[j] = primes_dac[j]^(moveright&(primes_dac[j]^primes_dac[j-1]));
        shuffleprimedaclen[j] = primes_daclen[j]^(moveright&(primes_daclen[j]^primes_daclen[j-1]));
      }
      shuffleprimedac[targetstart[i]] = targetdac[i];
      shuffleprimedaclen[targetstart[i]] = targetdaclen[i];
    }

    int outsideblock[primes_batches];
    for (int64_t i = 0;i < primes_batches;++i)
      outsideblock[i] = !batchtodo[i];
      // batchtodo[i] will change while block is processed

    proj P[2];
    elligator(&P[0],&P[1],&A);

    for (int64_t i = 0;i < targetlen;++i) {
      int64_t primelowerbound = primes[targetstart[i]];

      // P[0] on curve, P[1] on twist
      // exception: if i==targetlen-1, don't care about the point we won't use

      // restrictions on orders for P[0],P[1]:
      // have cleared all targetprime[j] for j<i (by multiplication or isogeny)
      // _if_ i>0, have also cleared outside primes (by multiplication)

      proj_cswap(&P[0],&P[1],-targetnegative[i]);
      if (i == 0) {
        // P[0] just came out of elligator; clear irrelevant primes
        clearpublicprimes(&P[0],&A24,outsideblock);

        for (int64_t t = 0;t < targetlen;++t)
          for (int64_t j = targetstart[t]+1;j < targetstop[t];++j)
            xMUL_dac(&P[0],&A24,0,&P[0],shuffleprimedac[j],shuffleprimedaclen[j],targetmaxdaclen[t]);

        // will replace P[1] before it is used so skip it here
      }

      // if targetnegative[i]: P[1] on curve, P[0] on twist
      // else: P[0] on curve, P[1] on twist
      // either way: have cleared outside primes from P[0]
      // for i>0: have cleared outside primes from P[1]

      proj K = P[0];
      for (int64_t j = i+1;j < targetlen;++j)
        xMUL_dac(&K,&A24,0,&K,targetdac[j],targetdaclen[j],targetmaxdaclen[j]);

      int64_t maskrightorder = fp_iszero(&K.z)-1;
      // maskrightorder is -1 with probability 1-1/targetprime[i],
      // which is at least 1-1/primelowerbound

      maskrightorder &= random_coin(targetprime[i]*(primelowerbound-1),primelowerbound*(targetprime[i]-1));
      // coin is -1 with probability (1-1/primelowerbound)/(1-1/targetprime[i])
      // so maskrightorder is now -1 with probability 1-1/primelowerbound
      crypto_declassify(&maskrightorder,sizeof maskrightorder);

      assert(maskrightorder >= -1);
      assert(maskrightorder <= 0);
      csidh_stattried[target[i]] += 1;
      csidh_statsucceeded[target[i]] -= maskrightorder;

      int64_t maskisogeny = maskrightorder&targetmask[i];

      // XXX: if i=0 and targetlen=2, could push 0 points
      if (i == targetlen-2 && targetlen > 2) {
        // push only one point through second-to-last isogeny
        // namely the one with sign matching the last isogeny
        // which is maybe in position P[1]...
        proj_cmov(&P[0],&P[1],-(targetnegative[i+1]^targetnegative[i]));
      }
      // if i==targetlen-2 && targetlen>2:
      //   if targetnegative[i+1]: P[1] on curve, P[0] on twist
      //   else: P[0] on curve, P[1] on twist
      // else:
      //   if targetnegative[i]: P[1] on curve, P[0] on twist
      //   else: P[0] on curve, P[1] on twist

      if (maskrightorder) {
        proj Anew = A;
        proj Pnew[2] = {P[0],P[1]};
        int64_t Pnewlen;
        if (i == targetlen-1)
          Pnewlen = 0; // skip pushing points through last isogeny
        else if (i == 0)
          Pnewlen = 1; // will replace second point
        else
          Pnewlen = 2;

        if (i == targetlen-2 && targetlen > 2)
          Pnewlen = 1;

        xISOG_matryoshka(&Anew,Pnew,Pnewlen,&K,targetprime[i],primes[targetstart[i]],primes[targetstop[i]-1]);

        proj_cmov(&A,&Anew,-maskisogeny);
        xA24(&A24,&A);
        if (Pnewlen > 0)
          proj_cmov(&P[0],&Pnew[0],-maskisogeny);
        if (Pnewlen > 1)
          proj_cmov(&P[1],&Pnew[1],-maskisogeny);
      }

      if (i == 0) {
        proj plus;
        // generate independent point on second curve
        // or on twist, opposite of first
        elligator(&plus,&P[1],&A);
        proj_cswap(&plus,&P[1],-targetnegative[i]);
        clearpublicprimes(&P[1],&A24,outsideblock);
        for (int64_t t = 0;t < targetlen;++t)
          for (int64_t j = targetstart[t]+1;j < targetstop[t];++j)
            xMUL_dac(&P[1],&A24,0,&P[1],shuffleprimedac[j],shuffleprimedaclen[j],targetmaxdaclen[t]);
      }

      // if i==targetlen-2 && targetlen>2:
      //   if targetnegative[i+1]: P[1] on curve, P[0] on twist
      //   else: P[0] on curve, P[1] on twist
      // else:
      //   if targetnegative[i]: P[1] on curve, P[0] on twist
      //   else: P[0] on curve, P[1] on twist

      // XXX: integrate the scalarmults below as much as possible into xISOG_matryoshka above

      if (i == targetlen-2 && targetlen > 2) {
        xMUL_dac(&P[0],&A24,0,&P[0],targetdac[i],targetdaclen[i],targetmaxdaclen[i]);
        P[1] = P[0];
      } else if (i < targetlen-1) {
        proj_cswap(&P[0],&P[1],-targetnegative[i]);
        // now back to: P[0] on curve, P[1] on twist

        xMUL_dac(&P[0],&A24,0,&P[0],targetdac[i],targetdaclen[i],targetmaxdaclen[i]);
        xMUL_dac(&P[1],&A24,0,&P[1],targetdac[i],targetdaclen[i],targetmaxdaclen[i]);
      }

      // if i==targetlen-2 && targetlen>2:
      //   if targetnegative[i+1]: P[0]=P[1] on twist
      //   else: P[0]=P[1] on curve
      // else:
      //   P[0] on curve, P[1] on twist

      for (int64_t j = targetstart[i];j < targetstop[i];++j)
        todo[j] += maskisogeny&int64mask_equal(j,targetindex[i]);

      batchtodo[target[i]] += maskrightorder;
      batchtodosum += maskrightorder;
      assert(batchtodo[target[i]] >= 0);
      assert(batchtodosum >= 0);
    }
  }

  fp_inv(&A.z);
  fp_mul2(&A.x,&A.z);
  A.z = fp_1;
  out->A = A.x;
}

/* includes public-key validation. */
bool csidh(public_key *out, public_key const *in, private_key const *priv)
{
    if (!validate(in)) {
        fp_random(&out->A);
        return false;
    }
    action(out, in, priv);
    return true;
}
