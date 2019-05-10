### bsaes - BitSliced AES
#### Yawning Angel (yawning at schwanenlied dot me)

> The AES operations in this package are not implemented using constant-time
> algorithms. An exception is when running on systems with enabled hardware
> support for AES that makes these operations constant-time.
>
> -- https://golang.org/pkg/crypto/aes/

bsaes is a portable pure-Go constant time AES implementation based on the
excellent code from [BearSSL](https://bearssl.org/).  On AMD64 systems with
AES-NI and a sufficiently recent Go runtime, it will transparently call
`crypto/aes` when `NewCipher` is invoked.

Features:

 * Constant time.

 * 32 bit and 64 bit variants, with the appropriate one selected at runtime.

 * Provides `crypto/cipher.Block`.

 * `crypto/cipher.ctrAble` support for less-slow CTR-AES mode.

 * `crypto/cipher.cbcDecAble` support for less-slow CBC-AES decryption.

 * `crypto/cipher.gcmAble` support for less-slow GCM-AES.  This includes
   a constant time GHASH.

 * The raw guts of the implementations provided as sub-packages, for people
   to use to implement [other things](https://git.schwanenlied.me/yawning/aez).

Benchmarks:

| Primitive                   | Version | ns/op  | MB/s   |
| --------------------------- | :-----: | -----: | -----: |
| ECB-AES128                  | ct32    | 914    | 17.50  |
| ECB-AES256                  | ct32    | 1268   | 12.62  |
| CTR-AES128 (16 KiB)         | ct32    | 472010 | 34.17  |
| CBC-AES128 Decrypt (16 KiB) | ct32    | 583238 | 28.09  |
| GCM-AES128 (16 KiB)         | ct32    | 605676 | 27.05  |
| ECB-AES128                  | ct64    | 932    | 17.16  |
| ECB-AES256                  | ct64    | 1258   | 12.72  |
| CTR-AES128 (16 KiB)         | ct64    | 296016 | 55.35  |
| CBC-AES128 Decrypt (16 KiB) | ct64    | 350047 | 46.81  |
| GCM-AES128 (16 KiB)         | ct64    | 435660 | 37.61  |

All numbers taken on an Intel i7-5600U with Turbo Boost disabled, running on
linux/amd64.
