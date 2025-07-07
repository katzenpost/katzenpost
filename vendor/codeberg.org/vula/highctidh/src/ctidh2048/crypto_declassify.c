#ifdef TIMECOP
#include <valgrind/memcheck.h>
#endif

#include "crypto_declassify.h"

void crypto_declassify(void *x, unsigned long long xlen)
{
#ifdef TIMECOP
	VALGRIND_MAKE_MEM_DEFINED(x,xlen);
#else
	(void) x;
	(void) xlen;
#endif
}
