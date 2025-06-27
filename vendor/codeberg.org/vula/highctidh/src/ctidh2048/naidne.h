#ifndef HIGHCTIDH_NAIDNE_H
#define HIGHCTIDH_NAIDNE_H

#if defined(__linux__)
#include <endian.h>
#elif defined(__FreeBSD__)
#include <sys/types.h>
#include <sys/endian.h>
#elif (defined(__APPLE__) || defined (__Darwin__))
#include <sys/types.h>
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>
#define htole32(x) OSSwapHostToLittleInt32(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)
#elif defined(__OpenBSD__)
#include <endian.h>
#elif defined(__sun)
#include <sys/byteorder.h>
#define htole32(x) LE_32(x)
#define htole64(x) LE_64(x)
#define le32toh(x) LE_32(x)
#define le64toh(x) LE_64(x)
#elif (defined(__Windows__) || defined(_WIN64) || defined(_WIN32))
#include <stdlib.h>
#if (BYTE_ORDER == LITTLE_ENDIAN)
#define htole32(x) (x)
#define le32toh(x) (x)
#define htole64(x) (x)
#define le64toh(x) (x)
#elif (BYTE_ORDER == BIG_ENDIAN)
#define htole32(x) _byteswap_ulong(x)
#define le32toh(x) _byteswap_ulong(x)
#define htole64(x) _byteswap_uint64(x)
#define le64toh(x) _byteswap_uint64(x)
#endif
#else
#include <endian.h>
#endif

#endif
