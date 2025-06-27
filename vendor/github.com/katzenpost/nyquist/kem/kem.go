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

// Package kem implments the PQNoise Key Encapsulation Mechanism function
// abstract interface and "standard" functions.
package kem // import "github.com/katzenpost/nyquist/kem"

import (
	"errors"

	"github.com/katzenpost/hpqc/kem"

	"github.com/katzenpost/nyquist/seec"
)

var (
	// ErrMalformedCiphertext is the error returns when a serialized
	// ciphertext is malformed.
	ErrMalformedCiphertext = errors.New("nyquist/kem: malformed ciphertext")
)

func GenerateKeypair(scheme kem.Scheme, genRand seec.GenRand) (kem.PublicKey, kem.PrivateKey) {
	seed, err := genRand(scheme.SeedSize())
	if err != nil {
		panic(err)
	}
	return scheme.DeriveKeyPair(seed)
}

func Enc(genRand seec.GenRand, pubTo kem.PublicKey) ([]byte, []byte, error) {
	ct, ss, err := pubTo.Scheme().Encapsulate(pubTo)
	if err != nil {
		// This should NEVER happen.
		panic("nyquist/kem: failed to encapsulate: " + err.Error())
	}
	return ct, ss, nil
}

func Dec(privateKey kem.PrivateKey, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != privateKey.Scheme().CiphertextSize() {
		return nil, ErrMalformedCiphertext
	}

	ss, err := privateKey.Scheme().Decapsulate(privateKey, ciphertext)
	if err != nil {
		// This should NEVER happen, all KEMs that are currently still
		// in the NIST competition return a deterministic random value
		// on decapsulation failure.
		panic("nyquist/kem: failed to decapsulate: " + err.Error())
	}

	return ss, nil
}
