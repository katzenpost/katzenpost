#ifdef TIMECOP
#include <valgrind/memcheck.h>
#endif

#include "crypto_classify.h"

void crypto_classify(void *x,unsigned long long xlen)
{
#ifdef TIMECOP
  VALGRIND_MAKE_MEM_UNDEFINED(x,xlen);
#else
  (void) x;
  (void) xlen;
#endif
}
