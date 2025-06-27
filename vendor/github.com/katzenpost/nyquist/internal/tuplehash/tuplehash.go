// Copyright (C) 2021 Oasis Labs Inc. All rights reserved.
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

// Package tuplehash implements TupleHash from NIST SP 800-15.
package tuplehash

import (
	"encoding/binary"
	"math"
	"math/bits"

	"golang.org/x/crypto/sha3"
)

var constN = []byte("TupleHash")

// Hasher is a TupleHash instance.
type Hasher struct {
	cShake sha3.ShakeHash
}

// Write writes the byte-encoded tuple b to the TupleHash.
func (h *Hasher) Write(b []byte) (int, error) {
	// Yes, panic is rude, but people are probably going to ignore the error
	// anyway, and this should never happen under any realistic scenario.
	l := uint64(len(b))
	if l > math.MaxUint64/8 {
		panic("nyquist/internal/tuplehash: invalid tuple size")
	}

	_, _ = h.cShake.Write(leftEncode(l * 8)) // in bits
	_, _ = h.cShake.Write(b)

	return int(l), nil
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (h *Hasher) Sum(b []byte, outputSize int) []byte {
	// TODO: Once we switch to Go 1.17, assert outputSize <= math.MaxInt.
	oSize := uint64(outputSize)
	if oSize <= 0 || oSize > math.MaxUint64/8 {
		panic("nyquist/internal/tuplehash: invalid output size")
	}

	cShake := h.cShake.Clone()

	_, _ = cShake.Write(rightEncode(oSize * 8)) // in bits
	digest := make([]byte, int(oSize))
	_, _ = cShake.Read(digest)
	return append(b, digest...)
}

// Clone creates a copy of an existing TupleHash instance.
func (h *Hasher) Clone() *Hasher {
	return &Hasher{
		cShake: h.cShake.Clone(),
	}
}

// New128 creates a new TupleHash128 instance with the specified customization string.
func New128(customizationString []byte) *Hasher {
	return doNew(128, customizationString)
}

// New256 creates a new TupleHash256 instance with the specified customization string.
func New256(customizationString []byte) *Hasher {
	return doNew(256, customizationString)
}

func doNew(securityStrength int, customizationString []byte) *Hasher {
	var cShake sha3.ShakeHash
	switch securityStrength {
	case 128:
		cShake = sha3.NewCShake128(constN, customizationString)
	case 256:
		cShake = sha3.NewCShake256(constN, customizationString)
	default:
		panic("nyquist/internal/tuplehash: invalid security strength")
	}

	return &Hasher{
		cShake: cShake,
	}
}

func leftEncode(x uint64) []byte {
	// Trim leading zero bytes, and prepend the length in bytes.
	if x <= 255 {
		// Special case, single byte.
		return []byte{1, byte(x)}
	}

	var b [9]byte
	binary.BigEndian.PutUint64(b[1:], x)
	nrZeroBytes := bits.LeadingZeros64(x) / 8
	b[nrZeroBytes] = byte(8 - nrZeroBytes)

	return b[nrZeroBytes:]
}

func rightEncode(x uint64) []byte {
	// Trim leading zero bytes, and append the length in bytes.
	if x <= 255 {
		// Special case, single byte.
		return []byte{byte(x), 1}
	}

	var b [9]byte
	binary.BigEndian.PutUint64(b[:], x)
	nrZeroBytes := bits.LeadingZeros64(x) / 8
	b[8] = byte(8 - nrZeroBytes)

	return b[nrZeroBytes:]
}
