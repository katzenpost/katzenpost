// Copyright (c) 2019 Oasis Labs Inc. <info@oasislabs.com>
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package deoxysii implements the Deoxys-II-256-128 MRAE algorithm.
//
// See: https://sites.google.com/view/deoxyscipher
package deoxysii

import (
	"crypto/cipher"
	"errors"
	"strconv"

	"github.com/oasisprotocol/deoxysii/internal/api"
	"github.com/oasisprotocol/deoxysii/internal/ct32"
	"github.com/oasisprotocol/deoxysii/internal/ct64"
	"github.com/oasisprotocol/deoxysii/internal/hardware"
)

const (
	// KeySize is Deoxys-II-256-128 key size in bytes.
	KeySize = 32

	// NonceSize is the Deoxys-II-256-128 nonce size in bytes.
	NonceSize = 15

	// TagSize is the Deoxys-II-256-128 authentication tag size
	// in bytes.
	TagSize = 16
)

var (
	// ErrOpen is the error returned when the message authentication
	// fails durring an Open call.
	ErrOpen = errors.New("deoxysii: message authentication failure")

	// ErrInvalidKeySize is the error returned when the key size is
	// invalid
	ErrInvalidKeySize = errors.New("deoxysii: invalid key size")

	// ErrInvalidNonceSize is the error returned when the nonce size
	// is invalid
	ErrInvalidNonceSize = errors.New("deoxysii: invalid nonce size")

	factory api.Factory
)

type deoxysII struct {
	inner api.Instance
}

// NonceSize returns the size of the nonce that must be passed to Seal
// and Open.
func (aead *deoxysII) NonceSize() int {
	return NonceSize
}

// Overhead returns the maximum difference between the lengths of a
// plaintext and its ciphertext.
func (aead *deoxysII) Overhead() int {
	return TagSize
}

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and appends the result to dst, returning the updated
// slice. The nonce must be NonceSize() bytes long and should be unique
// for all time, for a given key.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0]
// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
func (aead *deoxysII) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic(ErrInvalidNonceSize)
	}

	ret, out := sliceForAppend(dst, len(plaintext)+TagSize)
	aead.inner.E(nonce, out, additionalData, plaintext)

	return ret
}

// Open decrypts and authenticates ciphertext, authenticates the
// additional data and, if successful, appends the resulting plaintext
// to dst, returning the updated slice. The nonce must be NonceSize()
// bytes long and both it and the additional data must match the
// value passed to Seal.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0]
// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
//
// Even if the function fails, the contents of dst, up to its capacity,
// may be overwritten.
func (aead *deoxysII) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, ErrInvalidNonceSize
	}
	if len(ciphertext) < TagSize {
		return nil, ErrOpen
	}

	ret, out := sliceForAppend(dst, len(ciphertext)-TagSize)
	ok := aead.inner.D(nonce, out, additionalData, ciphertext)
	if !ok {
		// Do not release unauthenticated plaintext.
		for i := range out {
			out[i] = 0
		}
		return nil, ErrOpen
	}

	return ret, nil
}

// New creates a new cipher.AEAD instance backed by Deoxys-II-256-128
// with the provided key.
func New(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	return &deoxysII{
		inner: factory.New(key),
	}, nil
}

var _ cipher.AEAD = (*deoxysII)(nil)

func init() {
	if hardware.Factory != nil {
		factory = hardware.Factory
		return
	}

	switch strconv.IntSize {
	case 64:
		factory = ct64.Factory
	case 32:
		factory = ct32.Factory
	default:
		panic("deoxysii: failed to pick implementation")
	}
}
