#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "mont.h"
#include "poly.h"

void poly_mul(fp *c,const fp *a,long long alen,const fp *b,long long blen)
{
  if (alen < blen) {
    poly_mul(c,b,blen,a,alen);
    return;
  }
  if (!blen) return;
  if (blen == 1) {
    for (long long i = 0;i < alen;++i) {
      fp_mul3(&c[i],&a[i],&b[0]);
    }
    return;
  }

  /* now alen >= blen >= 2 */

  if (alen == 2) {
    fp_mul3(&c[0],&a[0],&b[0]);
    fp_mul3(&c[2],&a[1],&b[1]);

    fp a01; fp_add3(&a01,&a[0],&a[1]);
    fp b01; fp_add3(&b01,&b[0],&b[1]);
    fp_mul3(&c[1],&a01,&b01);
    fp_sub2(&c[1],&c[0]);
    fp_sub2(&c[1],&c[2]);

    /*
    fp_mul3(&c[1],&a[0],&b[1]);
    fp t;
    fp_mul3(&t,&a[1],&b[0]);
    fp_add2(&c[1],&t);
    */
    return;
  }

  if (blen == 2) {
    if (alen == 3) {
      fp_mul3(&c[0],&a[0],&b[0]);
      fp_mul3(&c[2],&a[1],&b[1]);
      fp b01; fp_add3(&b01,&b[0],&b[1]);
      fp a01; fp_add3(&a01,&a[0],&a[1]);
      fp_mul3(&c[1],&a01,&b01);
      fp_sub2(&c[1],&c[0]);
      fp_sub2(&c[1],&c[2]);
      fp_mul3(&c[3],&a[2],&b[1]);
      fp a2b0; fp_mul3(&a2b0,&a[2],&b[0]);
      fp_add2(&c[2],&a2b0);
      return;
    }
    if (alen == 4) {
      fp_mul3(&c[0],&a[0],&b[0]);
      fp_mul3(&c[2],&a[1],&b[1]);
      fp b01; fp_add3(&b01,&b[0],&b[1]);
      fp a01; fp_add3(&a01,&a[0],&a[1]);
      fp_mul3(&c[1],&a01,&b01);
      fp_sub2(&c[1],&c[0]);
      fp_sub2(&c[1],&c[2]);

      fp mid;
      fp_mul3(&mid,&a[2],&b[0]);
      fp_mul3(&c[4],&a[3],&b[1]);
      fp a23; fp_add3(&a23,&a[2],&a[3]);
      fp_mul3(&c[3],&a23,&b01);
      fp_sub2(&c[3],&mid);
      fp_sub2(&c[3],&c[4]);
      fp_add2(&c[2],&mid);

/*
      fp_mul3(&c[3],&a[2],&b[1]);
      fp a2b0; fp_mul3(&a2b0,&a[2],&b[0]);
      fp_add2(&c[2],&a2b0);
      fp_mul3(&c[4],&a[3],&b[1]);
      fp a3b0; fp_mul3(&a3b0,&a[3],&b[0]);
      fp_add2(&c[3],&a3b0);
*/
      return;
    }
  }

  if (blen == 3) {
    if (alen <= 3) {
      /* see eprint 2015/1247 */
      /* XXX: toom instead? */
      fp a10; fp_sub3(&a10,&a[1],&a[0]);
      fp b01; fp_sub3(&b01,&b[0],&b[1]);
      fp_mul3(&c[1],&a10,&b01);
      fp a20; fp_sub3(&a20,&a[2],&a[0]);
      fp b02; fp_sub3(&b02,&b[0],&b[2]);
      fp_mul3(&c[2],&a20,&b02);
      fp a21; fp_sub3(&a21,&a[2],&a[1]);
      fp b12; fp_sub3(&b12,&b[1],&b[2]);
      fp_mul3(&c[3],&a21,&b12);
      fp_mul3(&c[0],&a[0],&b[0]);
      fp_mul3(&c[4],&a[2],&b[2]);
      fp a1b1; fp_mul3(&a1b1,&a[1],&b[1]);
      fp t; fp_add3(&t,&a1b1,&c[0]);
      fp_add2(&c[1],&t);
      fp_add3(&t,&a1b1,&c[4]);
      fp_add2(&c[3],&t);
      fp_add2(&t,&c[0]);
      fp_add2(&c[2],&t);

      if (alen >= 4) {
        fp_mul3(&t,&a[3],&b[0]); fp_add2(&c[3],&t);
        fp_mul3(&t,&a[3],&b[1]); fp_add2(&c[4],&t);
        fp_mul3(&c[5],&a[3],&b[2]);
      }
      if (alen >= 5) {
        // this would be same mults, more adds:
        // a0b0
        // (a1-a0)(b0-b1) + a0b0 + a1b1
        // (a2-a0)(b0-b2) + a0b0 + a1b1 + a2b2
        // (a2-a1)(b1-b2) + a1b1 + a2b2 + a3b0
        // (a4-a2)(b0-b2) + a2b0 + a3b1 + a4b2
        // (a4-a3)(b1-b2) + a3b1 + a4b2
        // a4b2
        fp_mul3(&t,&a[4],&b[0]); fp_add2(&c[4],&t);
        fp_mul3(&t,&a[4],&b[1]); fp_add2(&c[5],&t);
        fp_mul3(&c[6],&a[4],&b[2]);
      }
      return;
    }
  }

  long long kara = (alen+1)/2;
  long long a1len = alen-kara;

  if (blen <= kara) { /* XXX: figure out best cutoff */
    fp c1[a1len+blen-1];
    poly_mul(c,a,kara,b,blen);
    poly_mul(c1,a+kara,a1len,b,blen);
    for (long long i = 0;i < blen-1;++i)
      fp_add2(&c[i+kara],&c1[i]);
    for (long long i = blen-1;i < a1len+blen-1;++i)
      c[i+kara] = c1[i];
    return;
  }

  long long b1len = blen-kara;

  fp a01[kara];
  fp b01[kara];

  for (long long i = 0;i < a1len;++i)
    fp_add3(&a01[i],&a[i],&a[i+kara]);
  for (long long i = a1len;i < kara;++i)
    a01[i] = a[i];

  for (long long i = 0;i < b1len;++i)
    fp_add3(&b01[i],&b[i],&b[i+kara]);
  for (long long i = b1len;i < kara;++i)
    b01[i] = b[i];

  fp c01[kara+kara-1];
  long long c1len = a1len+b1len-1;
  fp c1[c1len];

  poly_mul(c,a,kara,b,kara);
  poly_mul(c01,a01,kara,b01,kara);
  poly_mul(c1,a+kara,a1len,b+kara,b1len);

  fp mix;

  if (c1len < kara) {
    fp_sub3(&c[kara+kara-1],&c01[kara-1],&c[kara-1]);
    for (long long i = 0;i < c1len;++i) {
      fp_sub3(&mix,&c[kara+i],&c1[i]);
      fp_sub3(&c[i+2*kara],&c01[i+kara],&mix);
      fp_sub3(&c[i+kara],&mix,&c[i]);
      fp_add2(&c[i+kara],&c01[i]);
    }
    for (long long i = c1len;i < kara-1;++i) {
      fp_sub3(&c[i+2*kara],&c01[i+kara],&c[i+kara]);
      fp_sub2(&c[i+kara],&c[i]);
      fp_add2(&c[i+kara],&c01[i]);
    }
    return;
  }

  for (long long i = 0;i < c1len-kara;++i) {
    fp_sub3(&mix,&c[kara+i],&c1[i]);
    fp_sub3(&c[i+kara],&mix,&c[i]);
    fp_add2(&c[i+kara],&c01[i]);
    fp_sub3(&c[i+2*kara],&c01[i+kara],&mix);
    fp_sub2(&c[i+2*kara],&c1[i+kara]);
  }
  for (long long i = c1len-kara;i < kara-1;++i) {
    fp_sub3(&mix,&c[kara+i],&c1[i]);
    fp_sub3(&c[i+kara],&mix,&c[i]);
    fp_add2(&c[i+kara],&c01[i]);
    fp_sub3(&c[i+2*kara],&c01[i+kara],&mix);
  }
  fp_sub3(&c[kara+kara-1],&c01[kara-1],&c[kara-1]);
  fp_sub2(&c[kara+kara-1],&c1[kara-1]);
  for (long long i = kara-1;i < c1len;++i)
    c[i+2*kara] = c1[i];

  return;
}

void poly_mul_low(fp *c,long long clen,const fp *a,long long alen,const fp *b,long long blen)
{
  if (!alen) return;
  if (!blen) return;
  if (!clen) return;

  if (clen == alen+blen-1) {
    poly_mul(c,a,alen,b,blen);
    return;
  }
  if (clen*4 >= 3*(alen+blen-1)) { /* XXX: tune cutoff */
    fp ab[alen+blen-1];
    poly_mul(ab,a,alen,b,blen);
    for (long long i = 0;i < clen;++i)
      c[i] = ab[i];
    return;
  }

  if (alen < blen) {
    const fp *t = a; long long tlen = alen;
    a = b; alen = blen;
    b = t; blen = tlen;
  }
  if (alen > clen) alen = clen;
  if (blen > clen) blen = clen;

  if (blen == 1) {
    for (long long i = 0;i < clen;++i)
      fp_mul3(&c[i],&a[i],&b[0]);
    return;
  }

  assert(2 <= blen);
  assert(blen <= alen);
  assert(alen <= clen);
  assert(clen <= alen+blen-2);

  if (clen == 2) {
    fp_mul3(&c[0],&a[0],&b[0]);
    fp_mul3(&c[1],&a[0],&b[1]);
    fp t; fp_mul3(&t,&a[1],&b[0]);
    fp_add2(&c[1],&t);
    return;
  }

  if (blen == 2) {
    if (clen == 3) {
      fp_mul3(&c[0],&a[0],&b[0]);
      fp_mul3(&c[2],&a[1],&b[1]);
      fp b01; fp_add3(&b01,&b[0],&b[1]);
      fp a01; fp_add3(&a01,&a[0],&a[1]);
      fp_mul3(&c[1],&a01,&b01);
      fp_sub2(&c[1],&c[0]);
      fp_sub2(&c[1],&c[2]);
      fp a2b0; fp_mul3(&a2b0,&a[2],&b[0]);
      fp_add2(&c[2],&a2b0);
      return;
    }
  }

  if((1)) { /* XXX: tune this */
    long long a1len = alen/2;
    long long a0len = alen-a1len;
    fp a0[a0len];
    fp a1[a1len];
    for (long long i = 0;i < a0len;++i) a0[i] = a[2*i];
    for (long long i = 0;i < a1len;++i) a1[i] = a[2*i+1];
    /* a = a0(x^2) + x a1(x^2) */

    long long b1len = blen/2;
    long long b0len = blen-b1len;
    fp b0[b0len];
    fp b1[b1len];
    for (long long i = 0;i < b0len;++i) b0[i] = b[2*i];
    for (long long i = 0;i < b1len;++i) b1[i] = b[2*i+1];
    /* b = b0(x^2) + x b1(x^2) */

    fp a01[a0len];
    for (long long i = 0;i < a1len;++i) fp_add3(&a01[i],&a0[i],&a1[i]);
    if (a1len < a0len) a01[a1len] = a0[a1len];

    fp b01[b0len];
    for (long long i = 0;i < b1len;++i) fp_add3(&b01[i],&b0[i],&b1[i]);
    if (b1len < b0len) b01[b1len] = b0[b1len];

    long long c0len = a0len+b0len-1;
    if (c0len > (clen+1)/2) c0len = (clen+1)/2;

    fp c0[c0len];
    poly_mul_low(c0,c0len,a0,a0len,b0,b0len);

    long long c01len = a0len+b0len-1;
    if (c01len > clen/2) c01len = clen/2;

    fp c01[c01len];
    poly_mul_low(c01,c01len,a01,a0len,b01,b0len);

    long long c1len = a1len+b1len-1;
    if (c1len > clen/2) c1len = clen/2;

    fp c1[c1len];
    poly_mul_low(c1,c1len,a1,a1len,b1,b1len);

    /* XXX: use refined karatsuba */

    assert(c0len >= c01len);
    for (long long i = 0;i < c01len;++i)
      fp_sub2(&c01[i],&c0[i]);

    assert(c1len <= c01len);
    for (long long i = 0;i < c1len;++i)
      fp_sub2(&c01[i],&c1[i]);

    /* ab = c0(x^2) + x c01(x^2) + x^2 c1(x^2) */

    assert(2*(c0len-1) < clen);
    assert(2*c0len >= clen);
    assert(2*(c01len-1)+1 < clen);
    assert(2*c01len+1 >= clen);

    for (long long i = 0;i < c0len;++i) c[2*i] = c0[i];
    for (long long i = 0;i < c01len;++i) c[2*i+1] = c01[i];
    for (long long i = 0;i < c1len-1;++i) fp_add2(&c[2*i+2],&c1[i]);
    if (2*c1len < clen) fp_add2(&c[2*c1len],&c1[c1len-1]);

    return;
  }


  /* XXX: try mulders split */

  long long split = (alen+1)/2;

  if (split+split < clen) {
    fp ab[alen+blen-1];
    poly_mul(ab,a,alen,b,blen);
    for (long long i = 0;i < clen;++i)
      c[i] = ab[i];
    return;
  }

  long long a1len = alen-split;

  if (blen <= split) { /* XXX: figure out best cutoff */
    assert(split+blen-1 <= clen);
    assert(a1len+blen-1 >= clen-split);
    fp c1[clen-split];
    poly_mul(c,a,split,b,blen);
    poly_mul_low(c1,clen-split,a+split,a1len,b,blen);
    for (long long i = 0;i < blen-1;++i)
      fp_add2(&c[i+split],&c1[i]);
    for (long long i = blen-1;i+split < clen;++i)
      c[i+split] = c1[i];
    return;
  }

  assert(split+split >= clen);
  assert(split < clen);

  if (clen < split+split)
    poly_mul_low(c,clen,a,split,b,split);
  else {
    assert(clen == split+split);
    poly_mul(c,a,split,b,split);
    c[clen-1] = fp_0;
  }

  fp c01[clen-split];
  poly_mul_low(c01,clen-split,a,split,b+split,blen-split);

  fp c10[clen-split];
  poly_mul_low(c10,clen-split,a+split,alen-split,b,split);

  for (long long i = 0;i < clen-split;++i) {
    fp_add2(&c[i+split],&c01[i]);
    fp_add2(&c[i+split],&c10[i]);
  }

  return;
}

void poly_mul_selfreciprocal(fp *c,const fp *a,long long alen,const fp *b,long long blen)
{
  if (!alen) return;
  if (!blen) return;

  if (alen == 1 && blen == 1) {
    fp_mul3(&c[0],&a[0],&b[0]);
    return;
  }

  if (alen == 2 && blen == 2) {
    fp_mul3(&c[0],&a[0],&b[0]);
    fp_add3(&c[1],&c[0],&c[0]);
    c[2] = c[0];
    return;
  }

  if (alen == 3 && blen == 3) {
    fp_mul3(&c[0],&a[0],&b[0]);
    fp_mul3(&c[2],&a[1],&b[1]);
    fp a01; fp_add3(&a01,&a[0],&a[1]);
    fp b01; fp_add3(&b01,&b[0],&b[1]);
    fp_mul3(&c[1],&a01,&b01);
    fp_add2(&c[2],&c[0]);
    fp_sub2(&c[1],&c[2]);
    fp_add2(&c[2],&c[0]);
    c[3] = c[1];
    c[4] = c[0];
    return;
  }

  if (alen == 4 && blen == 4) {
    fp_mul3(&c[0],&a[0],&b[0]);
    fp_mul3(&c[3],&a[1],&b[1]);
    fp a01; fp_add3(&a01,&a[0],&a[1]);
    fp b01; fp_add3(&b01,&b[0],&b[1]);
    fp_mul3(&c[2],&a01,&b01);
    fp_sub2(&c[2],&c[0]);
    fp_sub3(&c[1],&c[2],&c[3]);
    fp_add2(&c[3],&c[0]);
    fp_add2(&c[3],&c[3]);
    c[4] = c[2];
    c[5] = c[1];
    c[6] = c[0];
    return;
  }

  if (alen == 5 && blen == 5) {
    /* XXX: toom instead? */
    fp a10; fp_sub3(&a10,&a[1],&a[0]);
    fp b01; fp_sub3(&b01,&b[0],&b[1]);
    fp_mul3(&c[1],&a10,&b01);
    fp a20; fp_sub3(&a20,&a[2],&a[0]);
    fp b02; fp_sub3(&b02,&b[0],&b[2]);
    fp_mul3(&c[2],&a20,&b02);
    fp a21; fp_sub3(&a21,&a[2],&a[1]);
    fp b12; fp_sub3(&b12,&b[1],&b[2]);
    fp_mul3(&c[3],&a21,&b12);
    fp_mul3(&c[0],&a[0],&b[0]);
    fp a1b1; fp_mul3(&a1b1,&a[1],&b[1]);
    fp a2b2; fp_mul3(&a2b2,&a[2],&b[2]);

    fp t; fp_add3(&t,&a1b1,&c[0]);
    fp_add2(&c[1],&t);
    fp_add2(&c[3],&c[1]);
    fp_add3(&c[4],&t,&a2b2);
    fp_add2(&c[4],&t);
    fp_add2(&c[2],&t);
    fp_add2(&c[2],&a2b2);
    fp_add2(&c[3],&a1b1);
    fp_add2(&c[3],&a2b2);
    c[5] = c[3];
    c[6] = c[2];
    c[7] = c[1];
    c[8] = c[0];
    return;
  }

  if (alen == blen && (alen&1)) {
    long long len0 = (alen+1)/2;
    long long len1 = alen/2;
    fp a0[len0];
    fp b0[len0];
    fp a1[len1];
    fp b1[len1];
    fp c0[len0+len0-1];
    fp c01[len0+len0-1];
    fp c1[len1+len1-1];

    assert(2*(len0-1) < alen);
    assert(2*(len1-1)+1 < alen);
    assert(len1 < len0);

    for (long long i = 0;i < len0;++i) a0[i] = a[2*i];
    for (long long i = 0;i < len0;++i) b0[i] = b[2*i];
    poly_mul_selfreciprocal(c0,a0,len0,b0,len0);

    for (long long i = 0;i < len1;++i) a1[i] = a[2*i+1];
    for (long long i = 0;i < len1;++i) b1[i] = b[2*i+1];
    poly_mul_selfreciprocal(c1,a1,len1,b1,len1);

    for (long long i = 0;i < len1;++i) fp_add2(&a0[i],&a1[i]);
    for (long long i = 0;i < len1;++i) fp_add2(&b0[i],&b1[i]);
    for (long long i = 0;i < len1;++i) fp_add2(&a0[i+1],&a1[i]);
    for (long long i = 0;i < len1;++i) fp_add2(&b0[i+1],&b1[i]);
    poly_mul_selfreciprocal(c01,a0,len0,b0,len0);

    for (long long i = 0;i < len0+len0-1;++i)
      fp_sub2(&c01[i],&c0[i]);
    for (long long i = 0;i < len1+len1-1;++i)
      fp_sub2(&c01[i],&c1[i]);
    for (long long i = 0;i < len1+len1-1;++i)
      fp_sub2(&c01[i+1],&c1[i]);
    for (long long i = 0;i < len1+len1-1;++i)
      fp_sub2(&c01[i+1],&c1[i]);
    for (long long i = 0;i < len1+len1-1;++i)
      fp_sub2(&c01[i+2],&c1[i]);

    for (long long i = 1;i < len0+len0-1;++i)
      fp_sub2(&c01[i],&c01[i-1]);

#ifdef DEBUG
// -Wunused-variable
    long long clen = alen+blen-1;
    assert(2*(len0+len0-2) < clen);
    assert(2*(len0+len0-3)+1 < clen);
    assert(2*(len1+len1-2)+2 < clen);
#endif
    for (long long i = 0;i < len0+len0-1;++i) c[2*i] = c0[i];
    for (long long i = 0;i < len0+len0-2;++i) c[2*i+1] = c01[i];
    for (long long i = 0;i < len1+len1-1;++i) fp_add2(&c[2*i+2],&c1[i]);
    return;
  }

  if (alen == blen && !(alen&1)) {
    long long half = alen/2;
    fp c0[alen-1];
    fp c1[alen-1];

    poly_mul(c0,a,half,b,half);
    poly_mul(c1,a,half,b+half,half);

    for (long long i = 0;i < alen+alen-1;++i) c[i] = fp_0;
    for (long long i = 0;i < alen-1;++i)
      fp_add2(&c[i],&c0[i]);
    for (long long i = 0;i < alen-1;++i)
      fp_add2(&c[alen+alen-2-i],&c0[i]);
    for (long long i = 0;i < alen-1;++i)
      fp_add2(&c[half+i],&c1[i]);
    for (long long i = 0;i < alen-1;++i)
      fp_add2(&c[alen+half-2-i],&c1[i]);
    return;
  }

  long long clen = alen+blen-1;
  poly_mul_low(c,(clen+1)/2,a,alen,b,blen);
  for (long long i = (clen+1)/2;i < clen;++i)
    c[i] = c[clen-1-i];
}

void poly_mul_high(fp *c,long long cstart,const fp *a,long long alen,const fp *b,long long blen)
{
  if (alen < blen) {
    poly_mul_high(c,cstart,b,blen,a,alen);
    return;
  }
  if (blen <= 0) return;

  assert(cstart >= 0);
  assert(cstart <= alen+blen-1);

  if (cstart == alen+blen-1) return;

  if (cstart == 0) {
    poly_mul(c,a,alen,b,blen);
    return;
  }
  if (cstart == alen+blen-2) {
    fp_mul3(&c[0],&a[alen-1],&b[blen-1]);
    return;
  }
  if (blen == 1) {
    for (long long i = cstart;i < alen+blen-1;++i)
      fp_mul3(&c[i-cstart],&a[i],&b[0]);
    return;
  }
  if (cstart == alen+blen-3) {
    fp_mul3(&c[0],&a[alen-2],&b[blen-1]);
    fp t;
    fp_mul3(&t,&a[alen-1],&b[blen-2]);
    fp_add2(&c[0],&t);
    fp_mul3(&c[1],&a[alen-1],&b[blen-1]);
    return;
  }

  fp arev[alen];
  fp brev[blen];
  for (long long i = 0;i < alen;++i)
    arev[alen-1-i] = a[i];
  for (long long i = 0;i < blen;++i)
    brev[blen-1-i] = b[i];

  fp crev[alen+blen-1-cstart];
  poly_mul_low(crev,alen+blen-1-cstart,arev,alen,brev,blen);
  for (long long i = cstart;i < alen+blen-1;++i)
    c[i-cstart] = crev[alen+blen-2-i];

/*
  fp ab[alen+blen-1];
  poly_mul(ab,a,alen,b,blen);
  for (long long i = cstart;i < alen+blen-1;++i)
    c[i-cstart] = ab[i];
  return;
*/
}

void poly_mul_mid(fp *c,long long cstart,long long clen,const fp *a,long long alen,const fp *b,long long blen)
{
  if (!alen) return;
  if (!blen) return;
  assert(0 <= cstart);
  assert(0 <= clen);
  assert(cstart+clen <= alen+blen-1);
  if (!clen) return;

  if (clen == 1) {
    c[0] = fp_0;
    if (alen > cstart) alen = cstart+1;
    long long i = 0;
    if (blen <= cstart) i = cstart-blen+1;
    for (;i < alen;++i) {
      fp t;
      fp_mul3(&t,&a[i],&b[cstart-i]);
      fp_add2(&c[0],&t);
    }
    return;
  }

  if (blen == 1) {
    for (long long i = 0;i < clen;++i)
      fp_mul3(&c[i],&a[cstart+i],&b[0]);
    return;
  }

  if (cstart > 0 && cstart+clen <= alen && (blen & 1)) {
    poly_mul_mid(c,cstart-1,clen,a,alen-1,b+1,blen-1);
    fp t;
    for (long long i = 0;i < clen;++i) {
      fp_mul3(&t,&a[cstart+i],&b[0]);
      fp_add2(&c[i],&t);
    }
    return;
  }

  if (clen == 2) {
    // basic plan:
    // c[0] = a[0]*b[cstart]+a[1]*b[cstart-1]+a[2]*b[cstart-2]+...
    // c[1] = a[0]*b[cstart+1]+a[1]*b[cstart]+a[2]*b[cstart-1]+...

    if (cstart == 1 && alen >= 3 && blen == 2) {
      // transposed karatsuba from hanrot--quercia--zimmermann
      // delta = a[1]*(b[0]-b[1])
      // c[0] = (a[0]+a[1])*b[1]+delta
      // c[1] = (a[1]+a[2])*b[0]-delta
      fp delta;
      fp_sub3(&delta,&b[0],&b[1]);
      fp_mul2(&delta,&a[1]);
      fp_add3(&c[0],&a[0],&a[1]);
      fp_mul2(&c[0],&b[1]);
      fp_add2(&c[0],&delta);
      fp_add3(&c[1],&a[1],&a[2]);
      fp_mul2(&c[1],&b[0]);
      fp_sub2(&c[1],&delta);
      return;
    }
    if (cstart == 3 && alen >= 5 && blen == 4) {
      // delta = a[1]*(b[2]-b[3])+a[3]*(b[0]-b[1])
      // c[0] = (a[0]+a[1])*b[3]+(a[2]+a[3])*b[1]+delta
      // c[1] = (a[1]+a[2])*b[2]+(a[3]+a[4])*b[0]-delta
      fp b01; fp_sub3(&b01,&b[0],&b[1]);
      fp b23; fp_sub3(&b23,&b[2],&b[3]);
      fp a1b23; fp_mul3(&a1b23,&a[1],&b23);
      fp a3b01; fp_mul3(&a3b01,&a[3],&b01);
      fp delta; fp_add3(&delta,&a1b23,&a3b01);
      fp a01; fp_add3(&a01,&a[0],&a[1]);
      fp a12; fp_add3(&a12,&a[1],&a[2]);
      fp a23; fp_add3(&a23,&a[2],&a[3]);
      fp a34; fp_add3(&a34,&a[3],&a[4]);
      fp_mul2(&a01,&b[3]);
      fp_mul2(&a12,&b[2]);
      fp_mul2(&a23,&b[1]);
      fp_mul2(&a34,&b[0]);
      fp_add3(&c[0],&a01,&a23);
      fp_add3(&c[1],&a12,&a34);
      fp_add2(&c[0],&delta);
      fp_sub2(&c[1],&delta);
      return;
    }
  }

  if (clen == 3 && cstart == 1 && blen == 2 && alen >= 4) {
    // c[0] = a[0]*b[1]+a[1]*b[0]
    // c[1] = a[1]*b[1]+a[2]*b[0]
    // c[2] = a[2]*b[1]+a[3]*b[0]
    fp b01;
    fp_sub3(&b01,&b[0],&b[1]);
    fp delta0;
    fp_mul3(&delta0,&a[1],&b01);
    fp delta1;
    fp_mul3(&delta1,&a[2],&b01);
    fp_add3(&c[0],&a[0],&a[1]);
    fp_add3(&c[1],&a[1],&a[2]);
    fp_add3(&c[2],&a[2],&a[3]);
    fp_mul2(&c[0],&b[1]);
    fp_mul2(&c[1],&b[1]);
    fp_mul2(&c[2],&b[0]);
    fp_add2(&c[0],&delta0);
    fp_add2(&c[1],&delta1);
    fp_sub2(&c[2],&delta1);
    return;
  }

  if (clen == 4 && cstart == 5 && blen == 6 && alen >= 9) {
    // c[0] = a[0]*b[5]+a[1]*b[4]+a[2]*b[3]+a[3]*b[2]+a[4]*b[1]+a[5]*b[0]
    // c[1] = a[1]*b[5]+a[2]*b[4]+a[3]*b[3]+a[4]*b[2]+a[5]*b[1]+a[6]*b[0]
    // c[2] = a[2]*b[5]+a[3]*b[4]+a[4]*b[3]+a[5]*b[2]+a[6]*b[1]+a[7]*b[0]
    // c[3] = a[3]*b[5]+a[4]*b[4]+a[5]*b[3]+a[6]*b[2]+a[7]*b[1]+a[8]*b[0]

    fp a01[6];
    for (long long i = 0;i < 6;++i) fp_add3(&a01[i],&a[i],&a[i+3]);

    fp b01[3];
    for (long long i = 0;i < 3;++i) fp_sub3(&b01[i],&b[i],&b[i+3]);

    poly_mul_mid(c,2,3,a01,5,b+3,3);
    poly_mul_mid(c+3,2,1,a01+3,3,b,3);

    fp delta[3];
    poly_mul_mid(delta,2,3,a+3,5,b01,3);

    fp_add2(&c[0],&delta[0]);
    fp_add2(&c[1],&delta[1]);
    fp_add2(&c[2],&delta[2]);
    fp_sub2(&c[3],&delta[0]);
    return;
  }

  if (clen == 5 && cstart == 3 && blen == 4 && alen >= 8) {
    // c[0] = a[0]*b[3]+a[1]*b[2]+a[2]*b[1]+a[3]*b[0]
    // c[1] = a[1]*b[3]+a[2]*b[2]+a[3]*b[1]+a[4]*b[0]
    // c[2] = a[2]*b[3]+a[3]*b[2]+a[4]*b[1]+a[5]*b[0]
    // c[3] = a[3]*b[3]+a[4]*b[2]+a[5]*b[1]+a[6]*b[0]
    // c[4] = a[4]*b[3]+a[5]*b[2]+a[6]*b[1]+a[7]*b[0]

    fp a01[6];
    fp_add3(&a01[0],&a[0],&a[2]);
    fp_add3(&a01[1],&a[1],&a[3]);
    fp_add3(&a01[2],&a[2],&a[4]);
    fp_add3(&a01[3],&a[3],&a[5]);
    fp_add3(&a01[4],&a[4],&a[6]);
    fp_add3(&a01[5],&a[5],&a[7]);

    fp b01[2];
    fp_sub3(&b01[0],&b[0],&b[2]);
    fp_sub3(&b01[1],&b[1],&b[3]);

    poly_mul_mid(c,1,3,a01,4,b+2,2);
    poly_mul_mid(c+3,1,2,a01+3,3,b,2);

    fp delta[3];
    poly_mul_mid(delta,1,3,a+2,4,b01,2);

    fp_add2(&c[0],&delta[0]);
    fp_add2(&c[1],&delta[1]);
    fp_add2(&c[2],&delta[2]);
    fp_sub2(&c[3],&delta[1]);
    fp_sub2(&c[4],&delta[2]);
    return;
  }

  if ((clen&1) && cstart == clen && blen == clen+1 && alen >= cstart+clen) {
    long long split = (clen+1)/2;
    assert(2*split == clen+1);

    fp a01[3*split-2];
    assert(3*split-2+split <= alen);
    for (long long i = 0;i < 3*split-2;++i) fp_add3(&a01[i],&a[i],&a[i+split]);

    fp b01[split];
    assert(2*split == blen);
    for (long long i = 0;i < split;++i) fp_sub3(&b01[i],&b[i],&b[i+split]);

    assert(clen <= 3*split-2);
    poly_mul_mid(c,split-1,split,a01,clen,b+split,split);

    assert(clen-1+split <= 3*split-2);
    poly_mul_mid(c+split,split-1,split-1,a01+split,clen-1,b,split);

    fp delta[split];
    poly_mul_mid(delta,split-1,split,a+split,clen,b01,split);

    for (long long i = 0;i < split;++i) fp_add2(&c[i],&delta[i]);
    for (long long i = 0;i < split-1;++i) fp_sub2(&c[i+split],&delta[i]);
    return;
  }

  if (!(clen&1) && cstart == clen-1 && blen == clen && alen >= cstart+clen) {
    // again transposed karatsuba from hanrot--quercia--zimmermann
    long long split = clen/2;

    fp a01[3*split-1];
    for (long long i = 0;i < 3*split-1;++i) fp_add3(&a01[i],&a[i],&a[i+split]);

    fp b01[split];
    for (long long i = 0;i < split;++i) fp_sub3(&b01[i],&b[i],&b[i+split]);

    poly_mul_mid(c,split-1,split,a01,2*split-1,b+split,split);
    poly_mul_mid(c+split,split-1,split,a01+split,2*split-1,b,split);

    fp delta[split];
    poly_mul_mid(delta,split-1,split,a+split,2*split-1,b01,split);

    for (long long i = 0;i < split;++i) {
      fp_add2(&c[i],&delta[i]);
      fp_sub2(&c[split+i],&delta[i]);
    }
    return;
  }

  if (cstart+cstart+clen < alen+blen) {
    fp ab[cstart+clen];
    poly_mul_low(ab,cstart+clen,a,alen,b,blen);
    for (long long i = 0;i < clen;++i)
      c[i] = ab[cstart+i];
    return;
  }

  fp ab[alen+blen-1-cstart];
  poly_mul_high(ab,cstart,a,alen,b,blen);
  for (long long i = 0;i < clen;++i)
    c[i] = ab[i];
  return;
}

long long poly_tree1size(long long n)
{
  if (n <= 1) return 0;
  if (n == 2) return 3;
  if (n == 3) return 7;

  long long m = n/2;
  long long left = poly_tree1size(m);
  long long right = poly_tree1size(n-m);
  return left+right+n+1;
}

/* input: P[0...2n-1] has n 2-coeff polys */
/* output: number of coeffs in product tree (minus n) */
/* tree itself (without P) is stored in T */
/* for n>=2, product is stored in final n+1 coeffs of T */
long long poly_tree1(fp *T,const fp *P,long long n)
{
  if (n <= 1) return 0;

  if (n == 2) {
    poly_mul(T,P,2,P+2,2);
    return 3;
  }

  if (n == 3) {
    poly_mul(T,P,2,P+2,2);
    poly_mul(T+3,T,3,P+4,2);
    return 7;
  }

  long long m = n/2;
  long long left = poly_tree1(T,P,m);
  long long right = poly_tree1(T+left,P+2*m,n-m);
  poly_mul(T+left+right,T+left-(m+1),m+1,T+left+right-(n-m+1),n-m+1);
  return left+right+n+1;
}

long long poly_eval_precomputesize(long long flen)
{
  if (flen <= 2) return 0;
  return flen;
}

void poly_eval_precompute(fp *precomp,long long flen,const proj *p)
{
  if (flen <= 2) return;

  fp pxpow[flen];
  fp pzpow[flen];

  pxpow[1] = p->x;
  pzpow[1] = p->z;
  for (long long i = 2;i < flen;++i) {
    fp_mul3(&pxpow[i],&pxpow[i-1],&p->x);
    fp_mul3(&pzpow[i],&pzpow[i-1],&p->z);
  }

  precomp[0] = pzpow[flen-1];
  precomp[flen-1] = pxpow[flen-1];
  for (long long i = 1;i < flen-1;++i)
    fp_mul3(&precomp[i],&pxpow[i],&pzpow[flen-1-i]);
}

/* assumes flen > 0 */
/* output: v = f[p] = f[0]+f[1]p+...+f[flen-1]p^(flen-1) */
/* i.e.: */
/* v = f[0]pz^(flen-1)+f[1]px pz^(flen-2)+...+f[flen-1]px^(flen-1) */
/* implicitly divided by pz^(flen-1) */
/* denominators are eliminated */
/*   since application always computes ratios of two values at some points */
void poly_eval_postcompute(fp *v,const fp *f,long long flen,const proj *p,const fp *precomp)
{
  assert(flen > 0);
  if (flen == 1) {
    *v = f[0];
    return;
  }
  if (flen == 2) {
    fp tmp;
    fp_mul3(v,&f[0],&p->z);
    fp_mul3(&tmp,&f[1],&p->x);
    fp_add2(v,&tmp);
    return;
  }

  fp_mul3(v,&f[0],&precomp[0]);

  for (long long i = 1;i < flen;++i) {
    fp tmp;
    fp_mul3(&tmp,&f[i],&precomp[i]);
    fp_add2(v,&tmp);
  }
}

void poly_eval(fp *v,const fp *f,long long flen,const proj *p)
{
  long long precompsize = poly_eval_precomputesize(flen);
  fp precomp[precompsize];
  poly_eval_precompute(precomp,flen,p);
  poly_eval_postcompute(v,f,flen,p,precomp);
}

/* assuming rlen >= 1, mdeg >= 0: */
/* input: m[0]+m[1]x+...+m[mdeg]x^mdeg */
/* output: pseudo-reciprocal r[0]+r[1]x+...+r[rlen-1]x^(rlen-1) */
/*   and d = positive power of m[mdeg] */
/* conventional reciprocal floor(x^(mdeg+rlen-1)/m) */
/*   is pseudo-reciprocal divided by d (if d is nonzero) */
void poly_pseudoreciprocal(fp *d,fp *r,long long rlen,const fp *m,long long mdeg)
{
  if (mdeg == 0) {
    r[rlen-1] = fp_1;
    for (long long i = 0;i < rlen-1;++i) r[i] = fp_0;
    *d = m[mdeg];
    return;
  }
  if (rlen == 1) {
    r[0] = fp_1;
    *d = m[mdeg];
    return;
  }
  if (rlen == 2) {
    /* can absorb into general case below */
    r[1] = m[mdeg];
    fp_neg2(&r[0],&m[mdeg-1]);
    fp_sq2(d,&m[mdeg]);
    return;
  }

  /* apply simpson recursive method for division */
  /* (often miscredited to newton) */
  /* XXX: remove redundancies as per harvey et al. */

  if (mdeg >= rlen) {
    /* divide m by x^(mdeg-(rlen-1)) */
    /* and truncate, which cannot affect result */
    m += mdeg-(rlen-1);
    mdeg = rlen-1;
  }

  long long top = (rlen+1)/2;
  long long bot = rlen-top;
  fp s[top];
  poly_pseudoreciprocal(d,s,top,m,mdeg);
  /* s/d is floor(x^(mdeg+top-1)/m) */
  /* i.e. s/d is x^(mdeg+top-1)/m+O(1/x) */
  /* i.e. ms is dx^(mdeg+top-1)+eps with eps in O(x^(mdeg-1)) */

  fp eps[mdeg];
  poly_mul_low(eps,mdeg,m,mdeg+1,s,top);

  /* ms(dx^(mdeg+top-1)-eps) */
  /*   = d^2x^(2*mdeg+2*top-2)-eps^2 */
  /*   with eps^2 in O(x^(2*mdeg-2)) */

  /* sdx^bot - s eps/x^(mdeg+2*top-1-rlen) */
  /* = s(dx^(mdeg+top-1)-eps)/x^(mdeg+2*top-1-rlen) */
  /*   = desired d^2 x^(mdeg+rlen-1)/m */
  /*   - undesired eps^2/mx^(mdeg+2*top-1-rlen) */
  /*   with the undesired part in O(1/x) */

  fp epss[bot];
  poly_mul_high(epss,mdeg+top-bot-1,eps,mdeg,s,top);

  for (long long i = 0;i < bot;++i)
    fp_neg2(&r[i],&epss[i]);
  for (long long i = 0;i < top;++i)
    fp_mul3(&r[i+bot],&s[i],d);

  fp_sq1(d);
}

long long poly_pseudoremainder_precomputesize(long long glen,long long flen)
{
  assert(flen >= glen);
  if (flen == glen) return 0;
  long long vlen = flen-glen;
  return vlen+1;
}

void poly_pseudoremainder_precompute(fp *precomp,long long glen,long long flen,const fp *m)
{
  assert(flen >= glen);
  if (flen == glen) return;
  long long vlen = flen-glen;
  fp *d = precomp; /* length 1 */
  fp *v = precomp+1; /* length vlen */
  poly_pseudoreciprocal(d,v,vlen,m,glen);
}

void poly_pseudoremainder_postcompute(fp *g,long long glen,const fp *f,long long flen,const fp *m,const fp *precomp)
{
  assert(flen >= glen);

  if (flen == glen) {
    for (long long i = 0;i < glen;++i)
      g[i] = f[i];
    return;
  }

  /* simplified version when m[glen] = 1: */
  /* v = floor(x^(flen-1)/m) is within O(1/x) of x^(flen-1)/m */
  /* v*f is within O(x^(flen-2)) of x^(flen-1)f/m */
  /* v*f/x^(flen-1) is within O(1/x) of f/m */
  /* q = floor(v*f/x^(flen-1)) is within O(1/x) of f/m */
  /* q*m is within O(x^(glen-1)) of f */
  /* finally, define g = f-q*m */

  long long vlen = flen-glen;
  const fp *d = precomp; /* length 1 */
  const fp *v = precomp+1; /* length vlen */
  /* floor(x^(flen-1)/m) = v/d */
  /* i.e., v is within O(1/x) of dx^(flen-1)/m */

  /* vf is within O(x^(flen-2)) of dx^(flen-1)f/m */
  /* vf/x^(flen-1) is within O(1/x) of df/m */
  /* mvf/x^(flen-1) is within O(x^(glen-1)) of df */

  fp vf[vlen];
  poly_mul_high(vf,flen-1,v,vlen,f,flen);

  fp qm[glen];
  poly_mul_low(qm,glen,vf,vlen,m,glen+1);

  for (long long i = 0;i < glen;++i) {
    fp_mul3(&g[i],&f[i],d);
    fp_sub2(&g[i],&qm[i]);
  }
}

/* assuming flen >= glen >= 1: */
/* reduce f[0]+f[1]x+f[2]x^2+...+f[flen-1]x^(flen-1) */
/* modulo m[0]+m[1]x+...+m[glen]x^glen */
/* to obtain pseudo-remainder g[0]+g[1]x+...+g[glen-1]x^(glen-1) */
/* and denominator d = m[glen]^(some nonnegative exponent) */
/* conventional remainder is pseudo-remainder divided by d (if d is nonzero) */
/* d is not returned since application eliminates denominators */
void poly_pseudoremainder(fp *g,long long glen,const fp *f,long long flen,const fp *m)
{
  long long precompsize = poly_pseudoremainder_precomputesize(glen,flen);
  fp precomp[precompsize];
  poly_pseudoremainder_precompute(precomp,glen,flen,m);
  poly_pseudoremainder_postcompute(g,glen,f,flen,m,precomp);

  /* XXX: try non-precomputation version too */
}

long long poly_multieval_unscaled_precomputesize(long long n,long long flen)
{
  if (n <= 0) return 0;
  if (n == 1)
    return poly_eval_precomputesize(flen);
  long long m = n/2;
  if (flen <= n)
    return
      poly_multieval_unscaled_precomputesize(m,flen)
      + poly_multieval_unscaled_precomputesize(n-m,flen);
  if (n == 2)
    return
      poly_pseudoremainder_precomputesize(n,flen)
      + poly_multieval_unscaled_precomputesize(1,n)
      + poly_multieval_unscaled_precomputesize(1,n);
  if (n == 3)
    return
      poly_pseudoremainder_precomputesize(n,flen)
      + poly_multieval_unscaled_precomputesize(2,n)
      + poly_multieval_unscaled_precomputesize(1,n);
  return
    poly_pseudoremainder_precomputesize(n,flen)
    + poly_multieval_unscaled_precomputesize(m,n)
    + poly_multieval_unscaled_precomputesize(n-m,n);
}

void poly_multieval_unscaled_precompute(fp *precomp,long long n,long long flen,const fp *P,const fp *T)
{
  if (n <= 0) return;

  if (n == 1) {
    proj p;
    fp_neg2(&p.x,&P[0]);
    p.z = P[1];
    poly_eval_precompute(precomp,flen,&p);
    return;
  }

  long long m = n/2;
  long long left = poly_tree1size(m);
  if (flen <= n) {
    poly_multieval_unscaled_precompute(precomp,m,flen,P,T);
    precomp += poly_multieval_unscaled_precomputesize(m,flen);
    poly_multieval_unscaled_precompute(precomp,n-m,flen,P+2*m,T+left);
    return;
  }

  if (n == 2) {
    poly_pseudoremainder_precompute(precomp,n,flen,T);
    precomp += poly_pseudoremainder_precomputesize(n,flen);
    poly_multieval_unscaled_precompute(precomp,1,n,P,0);
    precomp += poly_multieval_unscaled_precomputesize(1,n);
    poly_multieval_unscaled_precompute(precomp,1,n,P+2,0);
    return;
  }

  if (n == 3) {
    poly_pseudoremainder_precompute(precomp,n,flen,T+3);
    precomp += poly_pseudoremainder_precomputesize(n,flen);
    poly_multieval_unscaled_precompute(precomp,2,n,P,T);
    precomp += poly_multieval_unscaled_precomputesize(2,n);
    poly_multieval_unscaled_precompute(precomp,1,n,P+4,0);
    return;
  }

  long long right = poly_tree1size(n-m);
  poly_pseudoremainder_precompute(precomp,n,flen,T+left+right);
  precomp += poly_pseudoremainder_precomputesize(n,flen);
  poly_multieval_unscaled_precompute(precomp,m,n,P,T);
  precomp += poly_multieval_unscaled_precomputesize(m,n);
  poly_multieval_unscaled_precompute(precomp,n-m,n,P+2*m,T+left);
}

void poly_multieval_unscaled_postcompute(fp *v,long long n,const fp *f,long long flen,const fp *P,const fp *T,const fp *precomp)
{
  if (n <= 0) return;

  if (n == 1) {
    proj p;
    fp_neg2(&p.x,&P[0]);
    p.z = P[1];
    poly_eval_postcompute(v,f,flen,&p,precomp);
    return;
  }

  long long m = n/2;
  long long left = poly_tree1size(m);
  if (flen <= n) {
    /* must do this if flen <= n */
    /* can do this even for larger flen */
    poly_multieval_unscaled_postcompute(v,m,f,flen,P,T,precomp);
    precomp += poly_multieval_unscaled_precomputesize(m,flen);
    poly_multieval_unscaled_postcompute(v+m,n-m,f,flen,P+2*m,T+left,precomp);
    return;
  }

  fp g[n];

  if (n == 2) {
    poly_pseudoremainder_postcompute(g,n,f,flen,T,precomp);
    precomp += poly_pseudoremainder_precomputesize(n,flen);
    poly_multieval_unscaled_postcompute(v,1,g,n,P,0,precomp);
    precomp += poly_multieval_unscaled_precomputesize(1,n);
    poly_multieval_unscaled_postcompute(v+1,1,g,n,P+2,0,precomp);
    return;
  }

  if (n == 3) {
    poly_pseudoremainder_postcompute(g,n,f,flen,T+3,precomp);
    precomp += poly_pseudoremainder_precomputesize(n,flen);
    poly_multieval_unscaled_postcompute(v,2,g,n,P,T,precomp);
    precomp += poly_multieval_unscaled_precomputesize(2,n);
    poly_multieval_unscaled_postcompute(v+2,1,g,n,P+4,0,precomp);
    return;
  }

  long long right = poly_tree1size(n-m);
  poly_pseudoremainder_postcompute(g,n,f,flen,T+left+right,precomp);
  precomp += poly_pseudoremainder_precomputesize(n,flen);
  poly_multieval_unscaled_postcompute(v,m,g,n,P,T,precomp);
  precomp += poly_multieval_unscaled_precomputesize(m,n);
  poly_multieval_unscaled_postcompute(v+m,n-m,g,n,P+2*m,T+left,precomp);
}

void poly_multieval_unscaled(fp *v,long long n,const fp *f,long long flen,const fp *P,const fp *T)
{
  long long precompsize = poly_multieval_unscaled_precomputesize(n,flen);
  fp precomp[precompsize];
  poly_multieval_unscaled_precompute(precomp,n,flen,P,T);
  poly_multieval_unscaled_postcompute(v,n,f,flen,P,T,precomp);
}

/* same API as poly_multieval_unscaled */
/* except for a different input representation: */
/* r[0]/x^n+r[1]/x^(n-1)+...+r[n-1]/x */
/* is the scaled representation of f mod root */
/* where root is the product of the polys in P */
void poly_multieval_scaled(fp *v,long long n,const fp *r,const fp *P,const fp *T)
{
  if (n <= 0) return;
  if (n == 1) {
    v[0] = r[0];
    return;
  }
  if (n == 2) {
    fp g[1];
    poly_mul_mid(g,1,1,r,2,P+2,2);
    poly_multieval_scaled(v,1,g,P,0);
    poly_mul_mid(g,1,1,r,2,P,2);
    poly_multieval_scaled(v+1,1,g,P+2,0);
    return;
  }
  if (n == 3) {
    fp g[2];
    poly_mul_mid(g,1,2,r,3,P+4,2);
    poly_multieval_scaled(v,2,g,P,T);
    poly_mul_mid(g,2,1,r,3,T,3);
    poly_multieval_scaled(v+2,1,g,P+4,0);
    return;
  }

  long long m = n/2;
  long long left = poly_tree1size(m);
  long long right = poly_tree1size(n-m);

  fp g[n-m];
  poly_mul_mid(g,n-m,m,r,n,T+left+right-(n-m+1),n-m+1);
  poly_multieval_scaled(v,m,g,P,T);
  poly_mul_mid(g,m,n-m,r,n,T+left-(m+1),m+1);
  poly_multieval_scaled(v+m,n-m,g,P+2*m,T+left);
}

long long poly_multieval_chooseunscaled(long long n,long long flen)
{
  /* XXX: tune this */
  if (n <= 1) return 1;
  if (flen <= 1) return 1;
  return 0;
}

long long poly_multieval_precomputesize(long long n,long long flen)
{
  if (poly_multieval_chooseunscaled(n,flen))
    return poly_multieval_unscaled_precomputesize(n,flen);
  if (flen < n) flen = n;
  return flen;
}

void poly_multieval_precompute(fp *precomp,long long n,long long flen,const fp *P,const fp *T)
{
  if (poly_multieval_chooseunscaled(n,flen)) {
    poly_multieval_unscaled_precompute(precomp,n,flen,P,T);
    return;
  }
  if (flen < n) flen = n;
  long long m = n/2;
  long long left = poly_tree1size(m);
  long long right = poly_tree1size(n-m);
  fp denom;
  poly_pseudoreciprocal(&denom,precomp,flen,T+left+right,n);
}

void poly_multieval_postcompute(fp *v,long long n,const fp *f,long long flen,const fp *P,const fp *T,const fp *precomp)
{
  if (poly_multieval_chooseunscaled(n,flen)) {
    poly_multieval_unscaled_postcompute(v,n,f,flen,P,T,precomp);
    return;
  }

  /* now use scaled remainder tree */

  fp fcopy[n];
  if (flen < n) {
    /* XXX: or split n into smaller trees? */
    for (long long i = 0;i < flen;++i) fcopy[i] = f[i];
    for (long long i = flen;i < n;++i) fcopy[i] = fp_0;
    f = fcopy;
    flen = n;
  }

  const fp *rootinv = precomp; /* first flen entries are polynomial */

  /* rootinv/denom is within O(1/x) of x^(n+flen-1)/root */
  /* frootinv/(denom*x^(flen-1)) is within O(1/x) of f x^n/root */

  fp frootinv[n];
  poly_mul_mid(frootinv,flen-1,n,f,flen,rootinv,flen);
  poly_multieval_scaled(v,n,frootinv,P,T);
}

/* same API as poly_multieval_unscaled */
void poly_multieval(fp *v,long long n,const fp *f,long long flen,const fp *P,const fp *T)
{
  long long precompsize = poly_multieval_precomputesize(n,flen);
  fp precomp[precompsize];
  poly_multieval_precompute(precomp,n,flen,P,T);
  poly_multieval_postcompute(v,n,f,flen,P,T,precomp);
}

void poly_multiprod2(fp *T,long long n)
{
  if (n <= 1) return;

  long long m = n/2;
  poly_multiprod2(T,m);
  poly_multiprod2(T+3*m,n-m);

  fp X[2*n+1];

  /* T[0..2m] is left product */
  /* T[3m...2n+m] is right product */
  poly_mul(X,T,2*m+1,T+3*m,2*(n-m)+1);

  for (long long i = 0;i <= 2*n;++i) T[i] = X[i];
}

void poly_multiprod2_selfreciprocal(fp *T,long long n)
{
  if (n <= 1) return;

  long long m = n/2;
  poly_multiprod2_selfreciprocal(T,m);
  poly_multiprod2_selfreciprocal(T+3*m,n-m);

  fp X[2*n+1];

  /* T[0..2m] is left product */
  /* T[3m...2n+m] is right product */
  poly_mul_selfreciprocal(X,T,2*m+1,T+3*m,2*(n-m)+1);

  for (long long i = 0;i <= 2*n;++i) T[i] = X[i];
}
