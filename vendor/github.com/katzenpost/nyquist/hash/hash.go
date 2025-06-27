// Copyright (C) 2019, 2021 Yawning Angel. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Package hash implments the Noise Protocol Framework hash function abstract
// interface and standard hash functions.
package hash // import "github.com/katzenpost/nyquist/hash"

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
)

var (
	// SHA256 is the SHA256 hash function.
	SHA256 Hash = &hashSha256{}

	// SHA512 is the SHA512 hash function.
	SHA512 Hash = &hashSha512{}

	// BLAKE2s is the BLAKE2s hash function.
	BLAKE2s Hash = &hashBlake2s{}

	// BLAKE2b is the BLAKE2b hash function.
	BLAKE2b Hash = &hashBlake2b{}

	supportedHashes = map[string]Hash{
		"SHA256":  SHA256,
		"SHA512":  SHA512,
		"BLAKE2s": BLAKE2s,
		"BLAKE2b": BLAKE2b,
	}
)

// Hash is a collision-resistant cryptographic hash function factory.
type Hash interface {
	fmt.Stringer

	// New constructs a new `hash.Hash` instance.
	New() hash.Hash

	// Size returns the hash function's digest size in bytes (`HASHLEN`).
	Size() int
}

// FromString returns a Hash by algorithm name, or nil.
func FromString(s string) Hash {
	return supportedHashes[s]
}

type hashSha256 struct{}

func (h *hashSha256) String() string {
	return "SHA256"
}

func (h *hashSha256) New() hash.Hash {
	return sha256.New()
}

func (h *hashSha256) Size() int {
	return sha256.Size
}

type hashSha512 struct{}

func (h *hashSha512) String() string {
	return "SHA512"
}

func (h *hashSha512) New() hash.Hash {
	return sha512.New()
}

func (h *hashSha512) Size() int {
	return sha512.Size
}

type hashBlake2s struct{}

func (h *hashBlake2s) String() string {
	return "BLAKE2s"
}

func (h *hashBlake2s) New() hash.Hash {
	ret, _ := blake2s.New256(nil)
	return ret
}

func (h *hashBlake2s) Size() int {
	return blake2s.Size
}

type hashBlake2b struct{}

func (h *hashBlake2b) String() string {
	return "BLAKE2b"
}

func (h *hashBlake2b) New() hash.Hash {
	ret, _ := blake2b.New512(nil)
	return ret
}

func (h *hashBlake2b) Size() int {
	return blake2b.Size
}

// Register registers a new hash algorithm for use with `FromString()`.
func Register(hash Hash) {
	supportedHashes[hash.String()] = hash
}
