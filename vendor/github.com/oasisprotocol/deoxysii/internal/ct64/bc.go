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

package ct64

import (
	"encoding/binary"

	"github.com/oasisprotocol/deoxysii/internal/api"
	aes "github.com/oasisprotocol/deoxysii/internal/ext/aes/ct64"
)

func bcEncrypt(ciphertext []byte, stks *[api.STKCount][8]uint64, plaintext []byte) {
	_, _ = plaintext[:api.BlockSize], ciphertext[:api.BlockSize]

	var q [8]uint64
	aes.Load4xU32(&q, plaintext)
	aes.AddRoundKey(&q, stks[0][:])

	for i := 1; i <= api.Rounds; i++ {
		aes.Sbox(&q)
		aes.ShiftRows(&q)
		aes.MixColumns(&q)

		aes.AddRoundKey(&q, stks[i][:])
	}

	aes.Store4xU32(ciphertext, &q)
}

func bcKeystreamx4(ciphertext []byte, stks *[api.STKCount][8]uint64, nonce *[api.BlockSize]byte) {
	var q [8]uint64
	aes.RkeyOrtho(q[:], nonce[:])
	aes.AddRoundKey(&q, stks[0][:])

	for i := 1; i <= api.Rounds; i++ {
		aes.Sbox(&q)
		aes.ShiftRows(&q)
		aes.MixColumns(&q)

		aes.AddRoundKey(&q, stks[i][:])
	}

	_ = ciphertext[:api.BlockSize*4]
	aes.Store16xU32(ciphertext[0:], ciphertext[api.BlockSize:], ciphertext[2*api.BlockSize:], ciphertext[3*api.BlockSize:], &q)
}

func bcTagx1(tag []byte, stks *[api.STKCount][8]uint64, plaintext []byte) {
	_, _ = plaintext[:api.BlockSize], tag[:api.BlockSize]

	var q [8]uint64
	aes.Load4xU32(&q, plaintext)
	aes.AddRoundKey(&q, stks[0][:])

	for i := 1; i <= api.Rounds; i++ {
		aes.Sbox(&q)
		aes.ShiftRows(&q)
		aes.MixColumns(&q)

		aes.AddRoundKey(&q, stks[i][:])
	}

	tag0 := binary.LittleEndian.Uint32(tag[0:])
	tag1 := binary.LittleEndian.Uint32(tag[4:])
	tag2 := binary.LittleEndian.Uint32(tag[8:])
	tag3 := binary.LittleEndian.Uint32(tag[12:])

	aes.Ortho(q[:])
	var w [4]uint32
	aes.InterleaveOut(w[:], q[0], q[4])
	tag0 ^= w[0]
	tag1 ^= w[1]
	tag2 ^= w[2]
	tag3 ^= w[3]

	binary.LittleEndian.PutUint32(tag[0:], tag0)
	binary.LittleEndian.PutUint32(tag[4:], tag1)
	binary.LittleEndian.PutUint32(tag[8:], tag2)
	binary.LittleEndian.PutUint32(tag[12:], tag3)
}

func bcTagx4(tag []byte, stks *[api.STKCount][8]uint64, plaintext []byte) {
	_, _ = plaintext[:api.BlockSize*4], tag[:api.BlockSize]

	var q [8]uint64
	aes.Load16xU32(&q, plaintext[0:], plaintext[api.BlockSize:], plaintext[2*api.BlockSize:], plaintext[3*api.BlockSize:])
	aes.AddRoundKey(&q, stks[0][:])

	for i := 1; i <= api.Rounds; i++ {
		aes.Sbox(&q)
		aes.ShiftRows(&q)
		aes.MixColumns(&q)

		aes.AddRoundKey(&q, stks[i][:])
	}

	tag0 := binary.LittleEndian.Uint32(tag[0:])
	tag1 := binary.LittleEndian.Uint32(tag[4:])
	tag2 := binary.LittleEndian.Uint32(tag[8:])
	tag3 := binary.LittleEndian.Uint32(tag[12:])

	aes.Ortho(q[:])
	for i := 0; i < 4; i++ {
		var w [4]uint32
		aes.InterleaveOut(w[:], q[i], q[i+4])
		tag0 ^= w[0]
		tag1 ^= w[1]
		tag2 ^= w[2]
		tag3 ^= w[3]
	}

	binary.LittleEndian.PutUint32(tag[0:], tag0)
	binary.LittleEndian.PutUint32(tag[4:], tag1)
	binary.LittleEndian.PutUint32(tag[8:], tag2)
	binary.LittleEndian.PutUint32(tag[12:], tag3)
}
