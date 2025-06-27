/*
Copyright (c) 2019 Cloudflare. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Cloudflare nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

========================================================================

Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

// Package kem provides a unified interface for KEM schemes.
//
// A register of schemes is available in the package
//
//	github.com/katzenpost/hpqc/kem/schemes
package kem

import (
	"encoding"
	"errors"
)

// A KEM public key
type PublicKey interface {
	encoding.TextMarshaler
	encoding.BinaryMarshaler

	// Returns the scheme for this public key
	Scheme() Scheme

	Equal(PublicKey) bool
}

// A KEM private key
type PrivateKey interface {
	encoding.BinaryMarshaler

	// Returns the scheme for this private key
	Scheme() Scheme

	// Equal returns true if the two keys are equal.
	Equal(PrivateKey) bool

	// Public returns the public key related to this private key.
	Public() PublicKey
}

// A Scheme represents a specific instance of a KEM.
type Scheme interface {
	// Name of the scheme
	Name() string

	// GenerateKeyPair creates a new key pair.
	GenerateKeyPair() (PublicKey, PrivateKey, error)

	// Encapsulate generates a shared key ss for the public key and
	// encapsulates it into a ciphertext ct.
	Encapsulate(pk PublicKey) (ct, ss []byte, err error)

	// Returns the shared key encapsulated in ciphertext ct for the
	// private key sk.
	Decapsulate(sk PrivateKey, ct []byte) ([]byte, error)

	// UnmarshalBinaryPublicKey unmarshals a PublicKey from the provided buffer.
	UnmarshalBinaryPublicKey([]byte) (PublicKey, error)

	// UnmarshalBinaryPrivateKey unmarshals a PrivateKey from the provided buffer.
	UnmarshalBinaryPrivateKey([]byte) (PrivateKey, error)

	// UnmarshalTextPublicKey unmarshals a PublicKey from the provided text.
	UnmarshalTextPublicKey([]byte) (PublicKey, error)

	// UnmarshalTextPrivateKey unmarshals a PrivateKey from the provided text.
	UnmarshalTextPrivateKey([]byte) (PrivateKey, error)

	// Size of encapsulated keys.
	CiphertextSize() int

	// Size of established shared keys.
	SharedKeySize() int

	// Size of packed private keys.
	PrivateKeySize() int

	// Size of packed public keys.
	PublicKeySize() int

	// DeriveKeyPair deterministicallly derives a pair of keys from a seed.
	// Panics if the length of seed is not equal to the value returned by
	// SeedSize.
	DeriveKeyPair(seed []byte) (PublicKey, PrivateKey)

	// Size of seed used in DeriveKey
	SeedSize() int
}

var (
	// ErrTypeMismatch is the error used if types of, for instance, private
	// and public keys don't match
	ErrTypeMismatch = errors.New("types mismatch")

	// ErrSeedSize is the error used if the provided seed is of the wrong
	// size.
	ErrSeedSize = errors.New("wrong seed size")

	// ErrPubKeySize is the error used if the provided public key is of
	// the wrong size.
	ErrPubKeySize = errors.New("wrong size for public key")

	// ErrCiphertextSize is the error used if the provided ciphertext
	// is of the wrong size.
	ErrCiphertextSize = errors.New("wrong size for ciphertext")

	// ErrPrivKeySize is the error used if the provided private key is of
	// the wrong size.
	ErrPrivKeySize = errors.New("wrong size for private key")

	// ErrPubKey is the error used if the provided public key is invalid.
	ErrPubKey = errors.New("invalid public key")

	// ErrCipherText is the error used if the provided ciphertext is invalid.
	ErrCipherText = errors.New("invalid ciphertext")
)
