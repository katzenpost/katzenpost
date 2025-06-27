#include "randombytes.h"

#include <stdlib.h>

#include "crypto_classify.h"
#include "random_namespace.h"

#if defined(GETRANDOM) && (defined(__linux__) || defined(__sun))
#include <sys/random.h>

void randombytes(void *x, size_t l)
{
  ssize_t n;
  for (size_t i = 0; i < l; i += n)
    if (0 >= (n = getrandom((char *) x + i, l - i, 0)))
      exit(2);
  crypto_classify(x,l);
}

#elif (defined(GETRANDOM) && defined(__Darwin__))
#include <CommonCrypto/CommonRandom.h>
void randombytes(void *x, size_t l)
{
  ssize_t n;
  n = CCRandomGenerateBytes((char *) x, l);
  if (n != kCCSuccess) {
    exit(2);
  }
  crypto_classify(x,l);
}

#elif (defined(__Windows__) || defined(__WIN64) || defined(__WIN32))
/*
 *
 * XXX This is not secure or audited or even worth considering for anything
 * beyond proof of concept that the software can be built on Windows.
 *
 * DO NOT USE THIS FOR ANYTHING SERIOUS AT ALL - THIS IS NOT REASONABLE OR SAFE
 * AND HAS NOT BEEN AUDITED BY ANYONE. THIS IS A "IT COMPILES" LEVEL OF
 * COMPLETENESS.
 *
 * YOU HAVE BEEN WARNED. THIS, LIKE THE REST OF THE LIBRARY, IS NOT ELIGIBLE
 * FOR A CVE!
 */

ssize_t getrandom(char *buf, size_t buflen);
#include <windows.h>
#include <ntsecapi.h>
#define getrandom(x, y) RtlGenRandom(x, y)

void randombytes(void *x, size_t l)
{
  ssize_t n;
  for (size_t i = 0; i < l; i += n)
    if (0 >= (n = getrandom((char *) x + i, l - i)))
      exit(2);
  crypto_classify(x,l);
}

#else // Unix case where /dev/urandom exists

void randombytes(void *x, size_t l)
{
    static int fd = -1;
    ssize_t n;
    if (fd < 0 && 0 > (fd = open("/dev/urandom", O_RDONLY)))
        exit(1);
    for (size_t i = 0; i < l; i += n)
        if (0 >= (n = read(fd, (char *) x + i, l - i)))
            exit(2);
    crypto_classify(x,l);
}
#endif
