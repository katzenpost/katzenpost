// Copyright (C) 2021 Yawning Angel. All rights reserved.
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

// Package SEEC implments the Static-Ephemeral Entropy Combination (SEEC)
// scheme abstract interface and some predefined implementations.
package seec

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/katzenpost/nyquist/internal/tuplehash"

	"github.com/rfjakob/eme"
	"gitlab.com/yawning/bsaes.git"
)

// GenKey is a SEEC instance constructor, that takes an entropy source
// and a security parameter (lambda).
type GenKey func(io.Reader, int) (GenRand, error)

// GenRand is a keyed SEEC instance, that takes a length and returns
// the random entropy (using a randomly sampled r).
type GenRand func(int) ([]byte, error)

// GenKeyPassthrough constructs a new SEEC-Passthrough instance, backed by the
// provided entropy source.  If `rng` is nil, `crypto/rand.Reader` will be
// used.
func GenKeyPassthrough(rng io.Reader, lambda int) (GenRand, error) {
	if rng == nil {
		rng = rand.Reader
	}

	return func(sz int) ([]byte, error) {
		dst := make([]byte, sz)
		if _, err := io.ReadFull(rng, dst); err != nil {
			return nil, fmt.Errorf("nyquist/seec/passthrough: failed to read from entropy source: %w", err)
		}

		return dst, nil
	}, nil
}

// GenKeyPRFTupleHash constructs a new SEEC-PRF instance, backed by the
// provided entropy source, using TupleHash as the PRF, and lambda as
// the security strength in bits.  If `rng` is nil, `crypto/rand.Reader`
// will be used.
func GenKeyPRFTupleHash(rng io.Reader, lambda int) (GenRand, error) {
	var xof *tuplehash.Hasher
	switch lambda {
	case 128:
		xof = tuplehash.New128([]byte("nyquist/seec/prf/TupleHash128"))
	case 256:
		xof = tuplehash.New256([]byte("nyquist/seec/prf/TupleHash256"))
	default:
		return nil, fmt.Errorf("nyquist/seec/prf/tuplehash: invalid lambda: %d", lambda)
	}

	if rng == nil {
		rng = rand.Reader
	}

	sk := make([]byte, lambda/8)
	if _, err := io.ReadFull(rng, sk); err != nil {
		return nil, fmt.Errorf("nyquist/seec/prf/tuplehash: failed to read from entropy source: %w", err)
	}

	_, _ = xof.Write(sk)

	return func(sz int) ([]byte, error) {
		r := make([]byte, lambda/8)
		if _, err := io.ReadFull(rng, r); err != nil {
			return nil, fmt.Errorf("nyquist/seec/prf/tuplehash: failed to read from entropy source: %w", err)
		}

		x := xof.Clone()
		_, _ = x.Write(r)
		return x.Sum(nil, sz), nil
	}, nil
}

// GenKeyPRPAES constructs a new SEEC-PRP instance, backed by the provided
// entropy source, using AES as the PRP, and lambda as the security strength
// in bits.  If `rng` is nil, `crypto/rand.Reader` will be used.
//
// Warning: This uses EME (ECB-Mix-ECB) under the hood and requires that
// the output length of each GenRand call be a multiple of the AES block
// size.
func GenKeyPRPAES(rng io.Reader, lambda int) (GenRand, error) {
	switch lambda {
	case 128, 256:
	default:
		return nil, fmt.Errorf("nyquist/seec/prp/aes: invalid lambda: %d", lambda)
	}

	if rng == nil {
		rng = rand.Reader
	}

	sk := make([]byte, lambda/8)
	if _, err := io.ReadFull(rng, sk); err != nil {
		return nil, fmt.Errorf("nyquist/seec/prp/aes: failed to read from entropy source: %w", err)
	}

	aesBlk, err := bsaes.NewCipher(sk)
	if err != nil {
		return nil, fmt.Errorf("nyquist/seec/prp/aes: failed to initialize AES: %w", err)
	}

	blk := eme.New(aesBlk)

	return func(sz int) ([]byte, error) {
		if sz%16 != 0 {
			return nil, fmt.Errorf("nyquist/seec/prp/aes: invalid output lenght: %d", sz)
		}

		dst := make([]byte, sz)
		if _, err := io.ReadFull(rng, dst); err != nil {
			return nil, fmt.Errorf("nyquist/seec/prp/aes: failed to read from entropy source: %w", err)
		}

		var tweak [16]byte
		return blk.Encrypt(tweak[:], dst), nil
	}, nil
}
