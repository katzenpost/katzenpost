#ifndef HIGHCTIDH_INT32_SORT_H
#define HIGHCTIDH_INT32_SORT_H

#if defined(__AVX2__) && HIGHCTIDH_PORTABLE == 0

// This is the original high-ctidh x86_64 sorting code
#ifndef CGONUTS
#include "int32_sort_x86.c"
#endif // CGONUTS

#else /* fallback to portable C code: */

// This is from the Public Domain release of djbsort-20190516
#include "int32_sort.h"
#define int32 int32_t

#include "int32_minmax.h"

void int32_sort(int32 *x,long long n)
{
  long long top,p,q,r,i;

  if (n < 2) return;
  top = 1;
  while (top < n - top) top += top;

  for (p = top;p > 0;p >>= 1) {
    for (i = 0;i < n - p;++i)
      if (!(i & p))
        int32_MINMAX(x[i],x[i+p]);
    i = 0;
    for (q = top;q > p;q >>= 1) {
      for (;i < n - q;++i) {
        if (!(i & p)) {
          int32 a = x[i + p];
          for (r = q;r > p;r >>= 1)
            int32_MINMAX(a,x[i+r]);
      x[i + p] = a;
    }
      }
    }
  }
}

#endif /* end HIGHCTIDH_PORTABLE */
#endif /* HIGHCTIDH_INT32_SORT_H */
