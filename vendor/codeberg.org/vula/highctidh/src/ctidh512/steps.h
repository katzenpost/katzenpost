#ifndef STEPS_H
#define STEPS_H

#ifdef CGONUTS
#include "cgo.h"
#include "steps_namespace.h"
#endif // CGONUTS

/* assumes l >= 3, l odd */
/* guarantees (b,g) = (0,0) _or_ the following: */
/* b > 0; b is even; g > 0; 4*b*g <= l-1 */
/* tries to choose (b,g) sensibly */
void steps(long long *bs,long long *gs,long long l);

/* internal API for tuning to see bs,gs effects: */
void steps_override(long long bs,long long gs);

/* internal API for tuning to select bs,gs: */
int steps_guess(long long *bs,long long *gs,long long l);

#endif
