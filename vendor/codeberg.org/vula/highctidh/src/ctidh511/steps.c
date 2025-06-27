#include "steps.h"

static int steps_overridden;
static long long steps_override_bs;
static long long steps_override_gs;

void steps_override(long long bs,long long gs)
{
  steps_overridden = 1;
  steps_override_bs = bs;
  steps_override_gs = gs;
}

void steps(long long *bs,long long *gs,long long l)
{
  long long b,g;

  if (steps_overridden) {
    b = steps_override_bs;
    g = steps_override_gs;
  } else if (!steps_guess(&b,&g,l)) {
    b = 0;
    do {
      b += 2;
      g = (l-1)/(4*b);
    } while (g >= b);
  }

  /* enforce rules for b,g: */

  if (b < 0) b = 0;
  if (g < 0) g = 0;

  if (b&1) ++b;
  if (b)
    if (g > (l-1)/(4*b))
      g = (l-1)/(4*b);

  if (!g) b = 0;
  if (!b) g = 0;

  *bs = b;
  *gs = g;
}
