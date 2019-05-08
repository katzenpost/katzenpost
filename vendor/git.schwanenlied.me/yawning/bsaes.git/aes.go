// Copyright (c) 2017 Yawning Angel <yawning at schwanenlied dot me>
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

// Package bsaes is a pure-Go bitsliced constant time AES implementation.
package bsaes

import (
	"crypto/aes"
	"crypto/cipher"
	"math"
	"runtime"

	"git.schwanenlied.me/yawning/bsaes.git/ct32"
	"git.schwanenlied.me/yawning/bsaes.git/ct64"
)

// BlockSize is the AES block size in bytes.
const BlockSize = aes.BlockSize

var (
	useCryptoAES = false
	ctor         = ct64.NewCipher
)

type resetAble interface {
	Reset()
}

// NewCipher creates and returns a new cipher.Block.  The key argument should
// be the AES key, either 16, 24, or 32 bytes to select AES-128, AES-192, or
// AES-256.
func NewCipher(key []byte) (cipher.Block, error) {
	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, aes.KeySizeError(len(key))
	}
	if useCryptoAES {
		return aes.NewCipher(key)
	}

	blk := ctor(key)
	r := blk.(resetAble)
	runtime.SetFinalizer(r, (resetAble).Reset)

	return blk, nil
}

// UsingRuntime returns true iff this package is falling through to the
// runtime's implementation due to hardware support for constant time
// operation on the current system.
func UsingRuntime() bool {
	return useCryptoAES
}

func init() {
	// Fucking appengine doesn't have `unsafe`, so derive based off uintptr.
	// It's retarded that this isn't a constant in runtime or something.
	maxUintptr := uint64(^uintptr(0))
	switch maxUintptr {
	case math.MaxUint32:
		ctor = ct32.NewCipher
	case math.MaxUint64:
		ctor = ct64.NewCipher
	default:
		panic("bsaes: unsupported architecture")
	}
	useCryptoAES = isCryptoAESSafe()
}
