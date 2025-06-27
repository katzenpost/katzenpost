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
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/katzenpost/nyquist/cipher"
	"github.com/katzenpost/nyquist/hash"
)

// SymmetricState encapsulates all symmetric cryptography used by the Noise
// protocol during a handshake.
//
// Warning: There should be no reason to interact directly with this ever.
type SymmetricState struct {
	cipher cipher.Cipher
	hash   hash.Hash

	cs *CipherState

	ck []byte
	h  []byte

	hashLen int
}

// InitializeSymmetric initializes the SymmetricState with the initial
// chaining key and handshake hash, based on the protocol name.
func (ss *SymmetricState) InitializeSymmetric(protocolName []byte) {
	if len(protocolName) <= ss.hashLen {
		ss.h = make([]byte, ss.hashLen)
		copy(ss.h, protocolName)
	} else {
		h := ss.hash.New()
		_, _ = h.Write(protocolName)
		ss.h = h.Sum(nil)
	}

	ss.ck = make([]byte, 0, ss.hashLen)
	ss.ck = append(ss.ck, ss.h...)

	ss.cs.InitializeKey(nil)
}

// MixKey mixes the provided material with the chaining key, and initializes
// the encapsulated CipherState's key with the output.
func (ss *SymmetricState) MixKey(inputKeyMaterial []byte) {
	tempK := make([]byte, ss.hashLen)

	ss.hkdfHash(inputKeyMaterial, ss.ck, tempK)
	tempK = truncateTo32BytesMax(tempK)
	ss.cs.InitializeKey(tempK)
}

// MixHash mixes the provided data with the handshake hash.
func (ss *SymmetricState) MixHash(data []byte) {
	h := ss.hash.New()
	_, _ = h.Write(ss.h)
	_, _ = h.Write(data)
	ss.h = h.Sum(ss.h[:0])
}

// MixKeyAndHash mises the provided material with the chaining key, and mixes
// the handshake and initializes the encapsulated CipherState with the output.
func (ss *SymmetricState) MixKeyAndHash(inputKeyMaterial []byte) {
	tempH, tempK := make([]byte, ss.hashLen), make([]byte, ss.hashLen)

	ss.hkdfHash(inputKeyMaterial, ss.ck, tempH, tempK)
	ss.MixHash(tempH)
	tempK = truncateTo32BytesMax(tempK)
	ss.cs.InitializeKey(tempK)
}

// GetHandshakeHash returns the handshake hash `h`.
func (ss *SymmetricState) GetHandshakeHash() []byte {
	return ss.h
}

// EncryptAndHash encrypts and authenticates the plaintext, mixes the
// ciphertext with the handshake hash, appends the ciphertext to dst,
// and returns the potentially new slice.
func (ss *SymmetricState) EncryptAndHash(dst, plaintext []byte) []byte {
	var err error
	ciphertextOff := len(dst)
	if dst, err = ss.cs.EncryptWithAd(dst, ss.h, plaintext); err != nil {
		panic("nyquist/SymmetricState: encryptAndHash() failed: " + err.Error())
	}
	ss.MixHash(dst[ciphertextOff:])
	return dst
}

// DecryptAndHash authenticates and decrypts the ciphertext, mixes the
// ciphertext with the handshake hash, appends the plaintext to dst,
// and returns the potentially new slice.
func (ss *SymmetricState) DecryptAndHash(dst, ciphertext []byte) ([]byte, error) {
	// `dst` and `ciphertext` could alias, so save a copy of `h` so that the
	// `MixHash()` call can be called prior to `DecryptWithAd`.
	hPrev := make([]byte, 0, len(ss.h))
	hPrev = append(hPrev, ss.h...)

	ss.MixHash(ciphertext)

	return ss.cs.DecryptWithAd(dst, hPrev, ciphertext)
}

// Split returns a pair of CipherState objects for encrypted transport messages.
func (ss *SymmetricState) Split() (*CipherState, *CipherState) {
	tempK1, tempK2 := make([]byte, ss.hashLen), make([]byte, ss.hashLen)

	ss.hkdfHash(nil, tempK1, tempK2)
	tempK1 = truncateTo32BytesMax(tempK1)
	tempK2 = truncateTo32BytesMax(tempK2)

	c1, c2 := newCipherState(ss.cipher, ss.cs.maxMessageSize), newCipherState(ss.cipher, ss.cs.maxMessageSize)
	c1.InitializeKey(tempK1)
	c2.InitializeKey(tempK2)

	return c1, c2
}

// CipherState returns the SymmetricState's encapsualted CipherState.
//
// Warning: There should be no reason to call this, ever.
func (ss *SymmetricState) CipherState() *CipherState {
	return ss.cs
}

func (ss *SymmetricState) hkdfHash(inputKeyMaterial []byte, outputs ...[]byte) {
	// There is no way to sanitize the HKDF reader state.  While it is tempting
	// to just write a HKDF implementation that supports sanitization, neither
	// `crypto/hmac` nor the actual hash function implementations support
	// sanitization correctly either due to:
	//
	//  * `Reset()`ing a HMAC instance resets it to the keyed (initialized)
	//     state.
	//  * All of the concrete hash function implementations do not `Reset()`
	//    the cloned instance when `Sum([]byte)` is called.

	r := hkdf.New(ss.hash.New, inputKeyMaterial, ss.ck, nil)
	for _, output := range outputs {
		if len(output) != ss.hashLen {
			panic("nyquist/SymmetricState: non-HASHLEN sized output to HKDF-HASH")
		}
		_, _ = io.ReadFull(r, output)
	}
}

// Reset clears the SymmetricState, to prevent future calls.
//
// Warning: The transcript hash (`h`) is left intact to allow for clearing
// this state as early as possible, while preserving the ability to call
// `GetHandshakeHash`.
func (ss *SymmetricState) Reset() {
	if ss.ck != nil {
		ss.ck = nil
	}
	if ss.cs != nil {
		ss.cs.Reset()
		ss.cs = nil
	}
}

func newSymmetricState(cipher cipher.Cipher, hash hash.Hash, maxMessageSize int) *SymmetricState {
	return &SymmetricState{
		cipher:  cipher,
		hash:    hash,
		cs:      newCipherState(cipher, maxMessageSize),
		hashLen: hash.Size(),
	}
}
