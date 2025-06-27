### nyquist - A Noise Protocol Framework implementation
#### Yawning Angel (yawning at schwanenlied dot me)

This package implements the [Noise Protocol Framework][1].

#### Why?

> Yeah, well, I'm gonna go build my own theme park with blackjack and
> hookers.  In fact, forget the park.

#### Notes

It is assumed that developers using this package are familiar with the Noise
Protocol Framework specification.

As of revision 34 of the specification, the only standard functionality
that is NOT implemented is "10.2. The `fallback` modifier".

This package used to make a partial attempt to sanitize key material, but
the author is now convinced that it is fundementally a lost cause due to
several reasons including but not limited to copies on stack growth, the
lack of a `memset_s` equivalent, and lack of support by most cryptographic
primitives.  And no, memguard is not a good solution either.

This package will `panic` only if invariants are violated.  Under normal
use this situation should not occur ("normal" being defined as, "Yes, it
will panic if an invalid configuration is provided when initializing a
handshake").

Several non-standard protocol extensions are supported by this implementation:

 * The maximum message size can be set to an arbitrary value or entirely
   disabled, on a per-session basis.  The implementation will default to
   the value in the specification.

 * AEAD algorithms with authentication tags that are not 128 bits (16 bytes)
   in size should be supported.  While the package will not reject algorithms
   with tags sizes that are less than 128 bits, this is NOT RECOMMENED.

 * Non-standard DH, Cipher and Hash functions are trivial to support by
   implementing the appropriate interface, as long as the following
   constraints are met:

    * For any given DH scheme, all public keys must be `DHLEN` bytes in size.

    * For any given Hash function, `HASHLEN` must be at least 256 bits
      (32 bytes) in size.  The specification requires exactly 256 or 512
      bits, however this package will tollerate any length, greater than
      or equal to 256 bits.

    * AEAD implementations must be able to tollerate always being passed
      a key that is 256 bits (32 bytes) in size.

 * Non-standard (or unimplemented) patterns are trivial to support by
   implementing the appropriate interface.  The `pattern` sub-package
   includes a pattern validator that can verify a pattern against the
   specification's pattern validity rules.

 * A Cipher implementation backed by the Deoxys-II-256-128 MRAE primitive
   is provided.

The test vectors under `testdata` were shamelessly stolen out of the [Snow][2]
repository.

[1]: https://noiseprotocol.org/
[2]: https://github.com/mcginty/snow/tree/master/tests/vectors
