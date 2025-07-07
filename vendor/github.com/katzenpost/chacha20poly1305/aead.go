// aead.go - An AEAD_CHACHA20_POLY1305 implementation.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to chacha20poly1305, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// Package chacha20poly1305 implemnets the RFC 7539 AEAD_CHACHA20_POLY1305
// construct.  It depends on my ChaCha20 and Poly1305 libraries (and not
// golang.org/x/crypto for the latter), and attempts to be correct and easy to
// read over fast.
//
// When the golang.org/x/crypto maintainers feel like providing a sane
// interface to the Poly1305 code, this will switch to using that, but not
// before then.
package chacha20poly1305

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/poly1305"
	"github.com/katzenpost/chacha20"
)

const (
	// KeySize is the key length in bytes (32 bytes, 256 bits).
	KeySize = chacha20.KeySize

	// NonceSize is the nonce (IV) length in bytes (12 bytes, 96 bits).
	NonceSize = chacha20.INonceSize

	// Overhead is the tag length in bytes (16 bytes, 128 bits).
	Overhead = poly1305.TagSize
)

var (
	// ErrOpen is the error returned when an Open fails.
	ErrOpen = errors.New("chacha20poly1305: message authentication failed")

	paddingBytes [16]byte
)

// ChaCha20Poly1305 is an AEAD_CHACHA20_POLY1305 instance.
type ChaCha20Poly1305 struct {
	key [KeySize]byte
}

// NonceSize returns the size of the nonce that must be passed to Seal
// and Open.
func (a *ChaCha20Poly1305) NonceSize() int {
	return NonceSize
}

// Overhead returns the maximum difference between the lengths of a
// plaintext and its ciphertext.
func (a *ChaCha20Poly1305) Overhead() int {
	return Overhead
}

func (a *ChaCha20Poly1305) init(nonce []byte) (*chacha20.Cipher, *poly1305.MAC) {
	if len(nonce) != a.NonceSize() {
		panic("chacha20poly1305: len(nonce) != NonceSize()")
	}

	// First, a Poly1305 one-time key is generated from the 256-bit key
	// and nonce using the procedure described in Section 2.6.
	var polyKey [32]byte
	defer memwipe(polyKey[:])

	c, err := chacha20.New(a.key[:], nonce)
	if err != nil {
		panic("chacha20poly1305: failed to initialize chacha20: " + err.Error())
	}
	c.KeyStream(polyKey[:])
	c.Seek(1) // Set the initial counter to 1 in preparation for payload.

	m := poly1305.New(&polyKey)

	return c, m
}

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and appends the result to dst, returning the updated
// slice. The nonce must be NonceSize() bytes long and unique for all
// time, for a given key.
func (a *ChaCha20Poly1305) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	c, m := a.init(nonce)
	defer c.Reset()

	// Next, the ChaCha20 encryption function is called to encrypt the
	// plaintext, using the same key and nonce, and with the initial
	// counter set to 1.
	retLen := len(plaintext) + Overhead
	ret := make([]byte, len(plaintext), retLen)
	c.XORKeyStream(ret, plaintext)

	// Finally, the Poly1305 function is called with the Poly1305 key
	// calculated above, and a message constructed as a concatenation of
	// the following:

	// The AAD
	m.Write(additionalData)

	// padding1 -- the padding is up to 15 zero bytes, and it brings
	//  the total length so far to an integral multiple of 16.  If the
	//  length of the AAD was already an integral multiple of 16 bytes,
	//  this field is zero-length.
	padding1 := (16 - (len(additionalData) & 0x0f)) & 0x0f
	m.Write(paddingBytes[:padding1])

	// The ciphertext
	m.Write(ret)

	// padding2 -- the padding is up to 15 zero bytes, and it brings
	//  the total length so far to an integral multiple of 16.  If the
	//  length of the ciphertext was already an integral multiple of 16
	//  bytes, this field is zero-length.
	padding2 := (16 - (len(plaintext) & 0x0f)) & 0x0f
	m.Write(paddingBytes[:padding2])

	// The length of the additional data in octets (as a 64-bit
	//  little-endian integer).
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[0:], uint64(len(additionalData)))
	m.Write(lenBuf[:])

	// The length of the ciphertext in octets (as a 64-bit little-
	//  endian integer).
	binary.LittleEndian.PutUint64(lenBuf[0:], uint64(len(plaintext)))
	m.Write(lenBuf[:])

	// Return `dst | ciphertext | tag.
	ret = m.Sum(ret)
	return append(dst, ret...)
}

// Open decrypts and authenticates ciphertext, authenticates the
// additional data and, if successful, appends the resulting plaintext
// to dst, returning the updated slice. The nonce must be NonceSize()
// bytes long and both it and the additional data must match the
// value passed to Seal.
//
// Even if the function fails, the contents of dst, up to its capacity,
// may be overwritten.
func (a *ChaCha20Poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < Overhead {
		return nil, ErrOpen
	}
	ctLen := len(ciphertext) - Overhead

	c, m := a.init(nonce)
	defer c.Reset()

	// Derive the tag based on the data received, and validate.
	m.Write(additionalData)
	padding1 := (16 - (len(additionalData) & 0x0f)) & 0x0f
	m.Write(paddingBytes[:padding1])
	m.Write(ciphertext[:ctLen])
	padding2 := (16 - (ctLen & 0x0f)) & 0x0f
	m.Write(paddingBytes[:padding2])
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[0:], uint64(len(additionalData)))
	m.Write(lenBuf[:])
	binary.LittleEndian.PutUint64(lenBuf[0:], uint64(ctLen))
	m.Write(lenBuf[:])
	derivedTag := m.Sum(nil)
	if subtle.ConstantTimeCompare(ciphertext[ctLen:], derivedTag[:]) != 1 {
		memwipe(dst)
		return nil, ErrOpen
	}

	// Decrypt and return.
	ret := make([]byte, ctLen)
	c.XORKeyStream(ret, ciphertext[:ctLen])
	return append(dst, ret...), nil
}

// Reset clears all sensitive cryptographic material from a given instance
// so that it is no longer resident in memory.
func (a *ChaCha20Poly1305) Reset() {
	memwipe(a.key[:])
}

// New returns a new ChaCha20Poly1305 instance, keyed with a given key.
func New(key []byte) (*ChaCha20Poly1305, error) {
	if len(key) != KeySize {
		return nil, chacha20.ErrInvalidKey
	}

	a := &ChaCha20Poly1305{}
	copy(a.key[:], key)
	return a, nil
}

func memwipe(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

var _ cipher.AEAD = (*ChaCha20Poly1305)(nil)
