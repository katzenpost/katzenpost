#ifndef MONT_H
#define MONT_H

#include "uintbig.h"
#include "proj.h"
#include "mont_namespace.h"

void xA24(proj *A24,const proj *A);
void xDBL(proj *Q, proj const *P, const proj *A24, int Aaffine);
void xADD(proj *S, proj const *P, proj const *Q, proj const *PQ);
void xDBLADD(proj *R, proj *S, proj const *P, proj const *Q, proj const *PQ, proj const *A24, int Aaffine);
void xMUL_dac(proj *Q, proj const *A24, int Aaffine, proj const *P, long long dac, long long daclen, long long maxdaclen);
void xMUL(proj *Q, proj const *A, int Aaffine, proj const *P, uintbig const *k, long long kbits);
void xMUL_vartime(proj *Q, proj const *A, int Aaffine, proj const *P, uintbig const *k);

void xISOG_matryoshka(proj *A, proj *P, long long Plen, proj const *K, long long k, long long klower, long long kupper);
void xISOG(proj *A, proj *P, long long Plen, proj const *K, long long k);
void xISOG_old(proj *A, proj *P, proj const *K, long long k);

#endif
