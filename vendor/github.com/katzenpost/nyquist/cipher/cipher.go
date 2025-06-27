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

// Package cipher implments the Noise Protocol Framework cipher function
// abstract interface and standard cipher functions.
package cipher // import "github.com/katzenpost/nyquist/cipher"

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/oasisprotocol/deoxysii"
	"gitlab.com/yawning/bsaes.git"
	"golang.org/x/crypto/chacha20poly1305"
)

var supportedCiphers = map[string]Cipher{
	"ChaChaPoly": ChaChaPoly,
	"AESGCM":     AESGCM,
	"DeoxysII":   DeoxysII,
}

// Cipher is an AEAD algorithm factory.
type Cipher interface {
	fmt.Stringer

	// New constructs a new keyed `cipher.AEAD` instance, with the provided
	// key.
	New(key []byte) (cipher.AEAD, error)

	// EncodeNonce encodes a Noise nonce to a nonce suitable for use with
	// the `cipher.AEAD` instances created by `Cipher.New`.
	EncodeNonce(nonce uint64) []byte
}

// Rekeyable is the interface implemented by Cipher instances that have a
// `REKEY(k)` function specifically defined.
type Rekeyable interface {
	// Rekey returns a new 32-byte cipher key as a pseudorandom function of `k`.
	Rekey(k []byte) []byte
}

// FromString returns a Cipher by algorithm name, or nil.
func FromString(s string) Cipher {
	return supportedCiphers[s]
}

// ChaChaPoly is the ChaChaPoly cipher functions.
var ChaChaPoly Cipher = &cipherChaChaPoly{}

type cipherChaChaPoly struct{}

func (ci *cipherChaChaPoly) String() string {
	return "ChaChaPoly"
}

func (ci *cipherChaChaPoly) New(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

func (ci *cipherChaChaPoly) EncodeNonce(nonce uint64) []byte {
	var encodedNonce [12]byte // 96 bits
	binary.LittleEndian.PutUint64(encodedNonce[4:], nonce)
	return encodedNonce[:]
}

// AESGCM is the AESGCM cipher functions.
//
// Note: This Cipher implementation is always constant time, even on systems
// where the Go runtime library's is not.
var AESGCM Cipher = &cipherAesGcm{}

type cipherAesGcm struct{}

func (ci *cipherAesGcm) String() string {
	return "AESGCM"
}

func (ci *cipherAesGcm) New(key []byte) (cipher.AEAD, error) {
	block, err := bsaes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

func (ci *cipherAesGcm) EncodeNonce(nonce uint64) []byte {
	var encodedNonce [12]byte // 96 bits
	binary.BigEndian.PutUint64(encodedNonce[4:], nonce)
	return encodedNonce[:]
}

// DeoxysII is the DeoxysII cipher functions.
//
// Warning: This cipher is non-standard.
var DeoxysII Cipher = &cipherDeoxysII{}

type cipherDeoxysII struct{}

func (ci *cipherDeoxysII) String() string {
	return "DeoxysII"
}

func (ci *cipherDeoxysII) New(key []byte) (cipher.AEAD, error) {
	return deoxysii.New(key)
}

func (ci *cipherDeoxysII) EncodeNonce(nonce uint64) []byte {
	// Using the full nonce-space is fine, and big endian follows how
	// Deoxys-II encodes things internally.
	var encodedNonce [deoxysii.NonceSize]byte // 120 bits
	binary.BigEndian.PutUint64(encodedNonce[7:], nonce)
	return encodedNonce[:]
}

// Register registers a new cipher for use with `FromString()`.
func Register(cipher Cipher) {
	supportedCiphers[cipher.String()] = cipher
}
