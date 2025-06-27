#include "steps.h"

int steps_guess(long long *bs,long long *gs,long long l)
{
  if (l == 587) {
    *bs = 16;
    *gs = 9;
    return 1;
  }
  return 0;
}
