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

//go:build amd64 && !purego
// +build amd64,!purego

package hardware

import (
	"crypto/subtle"

	"golang.org/x/sys/cpu"

	"github.com/oasisprotocol/deoxysii/internal/api"
)

//
// AMD64 SSSE3 + AES-NI implementation.
//
// The assembly uses the following instructions over SSE2:
//  * PSHUFB (SSSE3)
//  * AESENC (AES-NI)
//

//go:noescape
func stkDeriveK(key *byte, derivedKs *[api.STKCount][api.STKSize]byte)

//go:noescape
func bcEncrypt(ciphertext *[api.BlockSize]byte, derivedKs *[api.STKCount][api.STKSize]byte, tweak *[api.TweakSize]byte, plaintext *[api.BlockSize]byte)

//go:noescape
func bcTag(tag *[16]byte, derivedKs *[api.STKCount][api.STKSize]byte, prefix byte, blockNr int, plaintext *byte, n int)

//go:noescape
func bcXOR(ciphertext *byte, derivedKs *[api.STKCount][api.STKSize]byte, tag *[16]byte, blockNr int, nonce *[16]byte, plaintext *byte, n int)

type aesniFactory struct{}

func (f *aesniFactory) Name() string {
	return "aesni"
}

func (f *aesniFactory) New(key []byte) api.Instance {
	var inner aesniInstance
	stkDeriveK(&key[0], &inner.derivedKs)
	return &inner
}

type aesniInstance struct {
	derivedKs [api.STKCount][api.STKSize]byte
}

func (inst *aesniInstance) E(nonce, dst, ad, msg []byte) {
	var (
		auth [api.TagSize]byte
		i    int
	)

	// Associated data
	adLen := len(ad)
	if fullBlocks := adLen / api.BlockSize; fullBlocks > 0 {
		bcTag(&auth, &inst.derivedKs, api.PrefixADBlock, 0, &ad[0], fullBlocks)
		i += fullBlocks
		adLen -= fullBlocks * api.BlockSize
	}
	if adLen > 0 {
		var aStar [16]byte
		copy(aStar[:], ad[len(ad)-adLen:])
		aStar[adLen] = 0x80

		bcTag(&auth, &inst.derivedKs, api.PrefixADFinal, i, &aStar[0], 1)
	}

	// Message authentication and tag generation
	msgLen := len(msg)
	i = 0
	if fullBlocks := msgLen / api.BlockSize; fullBlocks > 0 {
		bcTag(&auth, &inst.derivedKs, api.PrefixMsgBlock, 0, &msg[0], fullBlocks)
		i += fullBlocks
		msgLen -= fullBlocks * api.BlockSize
	}
	if msgLen > 0 {
		var mStar [16]byte
		copy(mStar[:], msg[len(msg)-msgLen:])
		mStar[msgLen] = 0x80

		bcTag(&auth, &inst.derivedKs, api.PrefixMsgFinal, i, &mStar[0], 1)
	}

	// 20. tag <- Ek(0001||0000||N, tag)
	var encNonce [api.BlockSize]byte
	copy(encNonce[1:], nonce)
	encNonce[0] = api.PrefixTag << api.PrefixShift
	bcEncrypt(&auth, &inst.derivedKs, &encNonce, &auth)

	// Message encryption
	var encTag [api.TagSize]byte
	copy(encTag[:], auth[:])
	encTag[0] |= 0x80
	encNonce[0] = 0 // 0x00 || nonce

	msgLen, i = len(msg), 0
	if fullBlocks := msgLen / api.BlockSize; fullBlocks > 0 {
		bcXOR(&dst[0], &inst.derivedKs, &encTag, 0, &encNonce, &msg[0], fullBlocks)
		i += fullBlocks
		msgLen -= fullBlocks * api.BlockSize
	}
	if msgLen > 0 {
		var tmp [api.BlockSize]byte

		copy(tmp[:], msg[i*16:])
		bcXOR(&tmp[0], &inst.derivedKs, &encTag, i, &encNonce, &tmp[0], 1)
		copy(dst[i*16:], tmp[:])
	}

	// Append the tag.
	copy(dst[len(dst)-api.TagSize:], auth[:])
}

func (inst *aesniInstance) D(nonce, dst, ad, ct []byte) bool {
	// Split out ct into ciphertext and tag.
	ctLen := len(ct) - api.TagSize
	ciphertext, tag := ct[:ctLen], ct[ctLen:]

	// Message decryption.
	var (
		i        int
		decNonce [api.BlockSize]byte
		decTag   [api.TagSize]byte
	)
	copy(decNonce[1:], nonce)
	copy(decTag[:], tag)
	decTag[0] |= 0x80
	if fullBlocks := ctLen / api.BlockSize; fullBlocks > 0 {
		bcXOR(&dst[0], &inst.derivedKs, &decTag, 0, &decNonce, &ciphertext[0], fullBlocks)
		i += fullBlocks
		ctLen -= fullBlocks * api.BlockSize
	}
	if ctLen > 0 {
		var tmp [api.BlockSize]byte

		copy(tmp[:], ciphertext[i*16:])
		bcXOR(&tmp[0], &inst.derivedKs, &decTag, i, &decNonce, &tmp[0], 1)
		copy(dst[i*16:], tmp[:])
	}

	// Associated data.
	var auth [api.TagSize]byte
	adLen := len(ad)
	i = 0
	if fullBlocks := adLen / api.BlockSize; fullBlocks > 0 {
		bcTag(&auth, &inst.derivedKs, api.PrefixADBlock, i, &ad[0], fullBlocks)
		i += fullBlocks
		adLen -= fullBlocks * api.BlockSize
	}
	if adLen > 0 {
		var aStar [16]byte
		copy(aStar[:], ad[len(ad)-adLen:])
		aStar[adLen] = 0x80

		bcTag(&auth, &inst.derivedKs, api.PrefixADFinal, i, &aStar[0], 1)
	}

	// Message authentication and tag generation.
	msgLen := len(dst)
	i = 0
	if fullBlocks := msgLen / api.BlockSize; fullBlocks > 0 {
		bcTag(&auth, &inst.derivedKs, api.PrefixMsgBlock, i, &dst[0], fullBlocks)
		i += fullBlocks
		msgLen -= fullBlocks * api.BlockSize
	}
	if msgLen > 0 {
		var mStar [16]byte
		copy(mStar[:], dst[len(dst)-msgLen:])
		mStar[msgLen] = 0x80

		bcTag(&auth, &inst.derivedKs, api.PrefixMsgFinal, i, &mStar[0], 1)
	}

	// 29. tag' <- Ek(0001||0000||N, tag')
	decNonce[0] = api.PrefixTag << api.PrefixShift
	bcEncrypt(&auth, &inst.derivedKs, &decNonce, &auth)

	// Tag verification.
	return subtle.ConstantTimeCompare(tag, auth[:]) == 1
}

func init() {
	if cpu.X86.HasSSSE3 && cpu.X86.HasAES {
		// Set the hardware inst.
		Factory = &aesniFactory{}
	}
}
