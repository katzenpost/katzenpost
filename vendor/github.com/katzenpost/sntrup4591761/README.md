sntrup4591761
=============

[![Build Status](https://github.com/companyzero/sntrup4591761/workflows/Build%20and%20Test/badge.svg)](https://github.com/companyzero/sntrup4591761/actions)
[![ISC License](https://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/companyzero/sntrup4591761)

# Streamlined NTRU Prime 4591^761

sntrup4591761 is a Go library implementing the [Streamlined NTRU Prime 4591<sup>761</sup> cryptosystem](https://ntruprime.cr.yp.to/ntruprime-20170816.pdf). Most of the code consists of a port of the reference C implementation.

## Constants

- PublicKeySize

The size of an encoded public key.

- PrivateKeySize

The size of an encoded private key.

- CiphertextSize

The size of a ciphertext encapsulating a shared key.

- SharedKeySize

The size of a shared key.

## Functions

- `GenerateKey(s io.Reader) (*[PublicKeySize]byte, *[PrivateKeySize]byte, error)`

GenerateKey returns a new a public/private key pair with randomness from s. GenerateKey will fail if randomness cannot be obtained from s.

- `Encapsulate(s io.Reader, publicKey *[PublicKeySize]byte) (*[CiphertextSize]byte, *[SharedKeySize]byte, error)`

Encapsulate generates a random shared key and encrypts it with the given public key. The shared key and its corresponding ciphertext are returned. Encapsulate will fail if randomness cannot be obtained from s.

- `Decapsulate(ciphertext *[CiphertextSize]byte, privateKey *[PrivateKeySize]byte) (*[SharedKeySize]byte, int)` 

Decapsulate uses a private key to decrypt a ciphertext, returning an encapsulated shared key. Decapsulate will return zero if the ciphertext is invalid.

## Examples

The library is accompanied by three small standalone applications demonstrating its use: *keygen*, *encap*, and *decap*. A test script is provided to exercise these applications comprehensively.

To build the bundled applications, ensure that the repository lies in your GOPATH and run `make`. Once built, the auxiliary test script can be triggered by invoking `./test`.

## Sage tests

A set of 128 different instances of NTRU Prime were simulated in Sage and their data compiled in testdata/sage128.gz. The *TestSage* Go test contrasts the results obtained by the library with those from the Sage implementation. Please note that this test can take seconds to complete.

### Running the tests

To run the Sage tests and other tests, ensure that the repository lies in your GOPATH and run `go test -v`.

## License

sntrup4591761 is licensed under the [copyfree](http://copyfree.org) ISC License.
