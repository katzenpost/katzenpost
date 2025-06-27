#include <string.h>
#include <assert.h>

#include "csidh.h"
#include "primes.h"
#include "random.h"

void csidh_private_withrng(private_key *priv, uintptr_t rng_context,
    ctidh_fillrandom rng_callback)
{
  memset(&priv->e, 0, sizeof(priv->e));
  long long pos = 0;
  long long w = 0;
  long long S = 0;
  for (long long b = 0;b < primes_batches;++b) {
    w = primes_batchsize[b];
    S = primes_batchbound[b];
    random_boundedl1(priv->e + pos,w,S, rng_context, rng_callback);
    pos += w;
  }
  assert(pos <= primes_num);
}

void csidh_private(private_key *priv)
{
	csidh_private_withrng(priv, (uintptr_t) priv, ctidh_fillrandom_default);
}
