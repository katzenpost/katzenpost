// This is from the Public Domain djbsort-20190516
/* this needs __attribute__((optimize)) >= 1 */

#ifndef HIGHCTIDH_INT32_MINMAX_H
#define HIGHCTIDH_INT32_MINMAX_H

#if ((defined(__x86_64__) || defined(__i86pc__))) && HIGHCTIDH_PORTABLE == 0

#define int32_MINMAX(a,b)			\
do { \
  int32 temp1; \
  __asm__( \
    ".att_syntax prefix\n\t" \
    "cmpl %1,%0\n\t" \
    "mov %0,%2\n\t" \
    "cmovg %1,%0\n\t" \
    "cmovg %2,%1\n\t" \
    : "+r"(a), "+r"(b), "=r"(temp1) \
    : \
    : "cc" \
  ); \
} while(0)

#else /* portable */

#define int32_MINMAX(a,b) do {			\
  register const int32_t big = (a > b ? a : b); \
  register const int32_t small = (a > b ? b : a); \
  a = small; \
  b = big; \
} while (0);

#endif /* portable */
typedef int no_empty_translation_units; // -> "warning: ISO C forbids an empty translation unit"
#endif /* HIGHCTIDH_INT32_MINMAX_H */
