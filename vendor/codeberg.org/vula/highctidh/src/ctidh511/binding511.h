#ifndef _BINDING_H
#define _BINDING_H

#ifdef CGONUTS

#include <stdlib.h>
#include <stdint.h>

#if 511 == BITS

void fillrandom_custom( void *const outptr, const size_t outsz, const uintptr_t context);
void highctidh_511_go_fillrandom(void *, void *, size_t);
#define NAMESPACEBITS(x) highctidh_511_##x
#define NAMESPACEGENERIC(x) highctidh_511_##x

__attribute__((weak))
void fillrandom_511_custom(
  void *const outptr,
  const size_t outsz,
  const uintptr_t context)
{
  highctidh_511_go_fillrandom((void *)context, outptr, outsz);
}
#endif

#endif

#endif
