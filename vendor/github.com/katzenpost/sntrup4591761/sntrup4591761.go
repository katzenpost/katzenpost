// Copyright (c) 2017 Company 0 LLC. All rights reserved.
// Use of this source code is governed by an ISC-style
// license that can be found in the LICENSE file.

// The sntrup4591761 package implements the Streamlined NTRU Prime 4591^761
// cryptosystem. See https://ntruprime.cr.yp.to/ntruprime-20170816.pdf.

package sntrup4591761

import (
	"crypto/sha512"
	"crypto/subtle"
	"io"

	"github.com/katzenpost/sntrup4591761/r3"
	"github.com/katzenpost/sntrup4591761/r3/mod3"
	"github.com/katzenpost/sntrup4591761/rq"
	"github.com/katzenpost/sntrup4591761/rq/modq"
	"github.com/katzenpost/sntrup4591761/zx"
)

const (
	PublicKeySize  = 1218
	PrivateKeySize = 1600
	CiphertextSize = 1047
	SharedKeySize  = 32
)

type (
	PrivateKey = [PrivateKeySize]byte
	PublicKey  = [PublicKeySize]byte
	Ciphertext = [CiphertextSize]byte
	SharedKey  = [SharedKeySize]byte
)

// deriveKey implements the deterministic part of GenerateKey.
func deriveKey(f, g, gr *[761]int8) (*PublicKey, *PrivateKey) {
	// public key
	f3r := new([761]int16)
	rq.Reciprocal3(f3r, f)
	h := new([761]int16)
	rq.Mult(h, f3r, g)
	pk := rq.Encode(h)

	// private key
	sk := new(PrivateKey)
	copy(sk[:], zx.Encode(f)[:])
	copy(sk[191:], zx.Encode(gr)[:])
	copy(sk[382:], pk[:])

	return pk, sk
}

// GenerateKey returns a new public/private key pair with randomness from s.
func GenerateKey(s io.Reader) (*PublicKey, *PrivateKey, error) {
	// Obtain a random g.
	g := new([761]int8)
	gr := new([761]int8)
	for {
		err := zx.RandomSmall(g, s)
		if err != nil {
			return nil, nil, err
		}
		if r3.Reciprocal(gr, g) == 0 {
			break
		}
	}

	// Obtain a random f.
	f := new([761]int8)
	err := zx.RandomTSmall(f, s)
	if err != nil {
		return nil, nil, err
	}

	pk, sk := deriveKey(f, g, gr)

	return pk, sk, nil
}

// createCipher implements the deterministic part of Encapsulate.
func createCipher(r *[761]int8, pk *PublicKey) (*Ciphertext, *SharedKey) {
	// Multiply the public key h by r to arrive at a ciphertext c.
	// The ciphertext's coefficients are rounded.
	h := rq.Decode(pk[:])
	c := new([761]int16)
	rq.Mult(c, h, r)
	rq.Round3(c, c)

	// The shared key is taken as the second half of the sha512 of the
	// random t-small element r.
	k := new(SharedKey)
	s := sha512.Sum512(zx.Encode(r)[:])
	copy(k[:], s[32:])

	// The ciphertext is prefixed with the first half of the sha512
	// hash as a confirmation token.
	cstr := new(Ciphertext)
	copy(cstr[:], s[:32])
	copy(cstr[32:], rq.EncodeRounded(c)[:])

	return cstr, k
}

// Encapsulate generates a random shared key and encrypts it with the given
// public key. The shared key and its corresponding ciphertext are returned.
// Randomness is obtained from s.
func Encapsulate(s io.Reader, pk *PublicKey) (*Ciphertext, *SharedKey, error) {
	r := new([761]int8)
	err := zx.RandomTSmall(r, s)
	if err != nil {
		return nil, nil, err
	}
	c, sk := createCipher(r, pk)

	return c, sk, nil
}

// Decapsulate uses a private key to decrypt a ciphertext, returning a
// shared key.
func Decapsulate(cstr *Ciphertext, sk *PrivateKey) (*SharedKey, int) {
	// Multiply c by f to arrive at t.
	f := zx.Decode(sk[:191])
	c := rq.DecodeRounded(cstr[32:])
	t := new([761]int16)
	rq.Mult(t, c, f)

	// Round t's coefficients to arrive at t3.
	t3 := new([761]int8)
	for i := 0; i < 761; i++ {
		t3[i] = mod3.Freeze(int32(modq.Freeze(int32(3 * t[i]))))
	}

	// Multiply t3 by gr to arrive at r.
	gr := zx.Decode(sk[191:])
	r := new([761]int8)
	r3.Mult(r, t3, gr)

	// Verify that r has the expected Hamming weight.
	w := 0
	for i := 0; i < 761; i++ {
		z := subtle.ConstantTimeEq(int32(r[i]), 0)
		w = subtle.ConstantTimeSelect(z, w, w+1)
	}
	ok := subtle.ConstantTimeEq(int32(w), 286)

	// Verify that r matches the ciphertext.
	h := rq.Decode(sk[(2 * 191):])
	hr := new([761]int16)
	rq.Mult(hr, h, r)
	rq.Round3(hr, hr)
	for i := 0; i < 761; i++ {
		ok &= subtle.ConstantTimeEq(int32(hr[i]-c[i]), 0)
	}

	// Hash r and compare it with the ciphertext.
	s := sha512.Sum512(zx.Encode(r)[:])
	ok &= subtle.ConstantTimeCompare(s[:32], cstr[:32])

	k := new(SharedKey)
	copy(k[:], s[32:])

	return k, ok
}
