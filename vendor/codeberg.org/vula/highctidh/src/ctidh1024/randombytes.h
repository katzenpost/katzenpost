#ifndef randombytes_h
#define randombytes_h

#ifndef _MSC_VER
#include <unistd.h>
#include <fcntl.h>
#else // e.g. (defined(__Windows__) || defined (__WIN64))
#include <basetsd.h>
#define ssize_t SSIZE_T
#include <windows.h>
#define SystemFunction036 NTAPI SystemFunction036
#include <ntsecapi.h>
#undef SystemFunction036
#pragma comment(lib, "advapi32.lib")
#endif

#include <stdlib.h>
#include <stdint.h>
#if defined(CGONUTS)
#include "cgo.h"
#define randombytes NAMESPACEBITS(randombytes)
#endif


void randombytes(void *x, size_t l);

#endif
