#ifndef SPX_RANDOMBYTES_H
#define SPX_RANDOMBYTES_H

extern void randombytes(unsigned char * x,unsigned long long xlen);

#define _randombytes(x, xlen) randombytes(x, xlen)

#endif
