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

package nyquist

import (
	goCipher "crypto/cipher"
	"errors"
	"math"

	"github.com/katzenpost/nyquist/cipher"
)

const (
	// SymmetricKeySize is the size a symmetric key in bytes.
	SymmetricKeySize = 32

	maxnonce = math.MaxUint64
)

var (
	errInvalidKeySize = errors.New("nyquist/CipherState: invalid key size")
	errNoExistingKey  = errors.New("nyquist/CipherState: failed to rekey, no existing key")

	zeroes [32]byte
)

// CipherState is a keyed AEAD algorithm instance.
type CipherState struct {
	cipher cipher.Cipher

	aead goCipher.AEAD
	k    []byte
	n    uint64

	maxMessageSize int
	aeadOverhead   int
}

// InitializeKey initializes sets the cipher key to `key`, and nonce to 0.
func (cs *CipherState) InitializeKey(key []byte) {
	if err := cs.setKey(key); err != nil {
		panic("nyquist/CipherState: failed to initialize key: " + err.Error())
	}
	cs.n = 0
}

func (cs *CipherState) setKey(key []byte) error {
	cs.Reset()

	switch len(key) {
	case 0:
	case SymmetricKeySize:
		var err error
		if cs.aead, err = cs.cipher.New(key); err != nil {
			return err
		}

		cs.aeadOverhead = cs.aead.Overhead()

		cs.k = make([]byte, SymmetricKeySize)
		copy(cs.k, key)
	default:
		return errInvalidKeySize
	}

	return nil
}

// HasKey returns true iff the CipherState is keyed.
func (cs *CipherState) HasKey() bool {
	return cs.aead != nil
}

// SetNonce sets the CipherState's nonce to `nonce`.
func (cs *CipherState) SetNonce(nonce uint64) {
	cs.n = nonce
}

// EncryptWithAd encrypts and authenticates the additional data and plaintext
// and increments the nonce iff the CipherState is keyed, and otherwise returns
// the plaintext.
//
// Note: The ciphertext is appended to `dst`, and the new slice is returned.
func (cs *CipherState) EncryptWithAd(dst, ad, plaintext []byte) ([]byte, error) {
	aead := cs.aead
	if aead == nil {
		return append(dst, plaintext...), nil
	}

	if cs.n == maxnonce {
		return nil, ErrNonceExhausted
	}

	if cs.maxMessageSize > 0 && len(plaintext)+cs.aeadOverhead > cs.maxMessageSize {
		return nil, ErrMessageSize
	}

	nonce := cs.cipher.EncodeNonce(cs.n)
	ciphertext := aead.Seal(dst, nonce, plaintext, ad)
	cs.n++

	return ciphertext, nil
}

// DecryptWihtAd authenticates and decrypts the additional data and ciphertext
// and increments the nonce iff the CipherState is keyed, and otherwise returns
// the plaintext.  If an authentication failure occurs, the nonce is not
// incremented.
//
// Note: The plaintext is appended to `dst`, and the new slice is returned.
func (cs *CipherState) DecryptWithAd(dst, ad, ciphertext []byte) ([]byte, error) {
	aead := cs.aead
	if aead == nil {
		return append(dst, ciphertext...), nil
	}

	if cs.n == maxnonce {
		return nil, ErrNonceExhausted
	}

	if cs.maxMessageSize > 0 && len(ciphertext) > cs.maxMessageSize {
		return nil, ErrMessageSize
	}

	nonce := cs.cipher.EncodeNonce(cs.n)
	plaintext, err := aead.Open(dst, nonce, ciphertext, ad)
	if err != nil {
		return nil, ErrOpen
	}
	cs.n++

	return plaintext, nil
}

// Rekey sets the CipherState's key to `REKEY(k)`.
func (cs *CipherState) Rekey() error {
	if !cs.HasKey() {
		return errNoExistingKey
	}

	var newKey []byte
	if rekeyer, ok := (cs.cipher).(cipher.Rekeyable); ok {
		// The cipher function set has a specific `REKEY` function defined.
		newKey = rekeyer.Rekey(cs.k)
	} else {
		// The cipher function set has no `REKEY` function defined, use the
		// default generic implementation.
		nonce := cs.cipher.EncodeNonce(maxnonce)
		newKey = cs.aead.Seal(nil, nonce, zeroes[:], nil)

		// "defaults to returning the first 32 bytes"
		newKey = truncateTo32BytesMax(newKey)
	}

	err := cs.setKey(newKey)

	return err
}

// Reset sets the CipherState to a un-keyed state.
func (cs *CipherState) Reset() {
	if cs.k != nil {
		cs.k = nil
	}
	if cs.aead != nil {
		cs.aead = nil
		cs.aeadOverhead = 0
	}
}

func newCipherState(cipher cipher.Cipher, maxMessageSize int) *CipherState {
	return &CipherState{
		cipher:         cipher,
		maxMessageSize: maxMessageSize,
	}
}
