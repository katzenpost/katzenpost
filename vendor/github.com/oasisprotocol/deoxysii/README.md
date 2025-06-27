### deoxysii - Deoxys-II-256-128 for Go

[![Build status][github-ci-tests-badge]][github-ci-tests-link]
[![GoDoc][godoc-badge]][godoc-link]

[github-ci-tests-badge]: https://github.com/oasisprotocol/deoxysii/workflows/ci-tests/badge.svg
[github-ci-tests-link]: https://github.com/oasisprotocol/deoxysii/actions?query=workflow:ci-tests
[godoc-badge]: https://godoc.org/github.com/oasisprotocol/deoxysii?status.svg
[godoc-link]: https://godoc.org/github.com/oasisprotocol/deoxysii

This package provides a "from-the-paper" implementation of the
[Deoxys-II-256-128 v1.43][1] algorithm from the [final CAESAR portfolio][2].

#### Implementations

 * (`ct32`) Portable 32 bit constant time implementation (Extremely slow).

 * (`ct64`) Portable 64 bit constant time implementation (Extremely slow).

 * (`aesni`) SSSE3 + AESNI implementation for `amd64`

 * (`vartime`) Portable and variable time (insecure) implementation,
   for illustrative purposes (tested/benchmarked but never reachable
   or usable by external consumers).

#### Notes

Performance for the AES-NI implementation still has room for improvement,
however given that the Deoxys-BC-384 tweakable block cipher has 3 more
rounds than AES-256, and Deoxys-II will do two passes over the data
payload, it is likely reasonably close to what can be expected.

The pure software constant time implementation would benefit considerably
from vector optimizations as the amount of internal paralleism is quite
high, making it well suited to be implemented with [bitslicing][3].
Additionally a rather ludicrous amount of time is spent implementing the
`h` permutation in software, that can be replaced with a single `PSHUFB`
instruction.

[1]: https://drive.google.com/file/d/1IUELtBUdp6vrY8uhxHhycsGuSH_XlpMJ/view?usp=drive_web
[2]: https://competitions.cr.yp.to/caesar-submissions.html
[3]: https://eprint.iacr.org/2009/129.pdf
