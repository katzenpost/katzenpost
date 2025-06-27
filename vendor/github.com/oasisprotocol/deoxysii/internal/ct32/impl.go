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

// Package ct32 provides a portable constant time Deoxys-II-256-128
// implementation intended for 32 bit processors.
//
// Performance is likely to be attrocious, as not much effort has been spent on
// optimization, under the view that it's unlikely to ever actually be really
// good without hardware accelerated AES.
package ct32

import (
	"crypto/subtle"

	"github.com/oasisprotocol/deoxysii/internal/api"
)

var Factory api.Factory = &ct32Factory{}

type ct32Factory struct{}

func (f *ct32Factory) Name() string {
	return "ct32"
}

func (f *ct32Factory) New(key []byte) api.Instance {
	var inner ct32Instance

	var derivedKs [api.STKCount][api.STKSize]byte
	api.STKDeriveK(key, &derivedKs)
	derivedKsOrtho(&inner.derivedKQs, &derivedKs)

	return &inner
}

type ct32Instance struct {
	derivedKQs [api.STKCount][8]uint32
}

func (inst *ct32Instance) E(nonce, dst, ad, msg []byte) {
	var (
		stks   [api.STKCount][8]uint32
		tweaks [2][api.TweakSize]byte
		i, j   int
	)

	// Associated data.
	adLen := len(ad)
	var auth [api.TagSize]byte
	for i = 0; adLen >= 2*api.BlockSize; i += 2 {
		api.EncodeTagTweak(&tweaks[0], api.PrefixADBlock, i)
		api.EncodeTagTweak(&tweaks[1], api.PrefixADBlock, i+1)

		deriveSubTweakKeysx2(&stks, &inst.derivedKQs, &tweaks)
		bcTagx2(auth[:], &stks, ad[i*api.BlockSize:])
		adLen -= 2 * api.BlockSize
	}
	for ; adLen >= api.BlockSize; i++ {
		api.EncodeTagTweak(&tweaks[0], api.PrefixADBlock, i)

		deriveSubTweakKeysx1(&stks, &inst.derivedKQs, &tweaks[0])
		bcTagx1(auth[:], &stks, ad[i*api.BlockSize:])
		adLen -= api.BlockSize
	}
	if adLen > 0 {
		api.EncodeTagTweak(&tweaks[0], api.PrefixADFinal, i)

		var aStar [api.BlockSize]byte
		copy(aStar[:], ad[len(ad)-adLen:])
		aStar[adLen] = 0x80

		deriveSubTweakKeysx1(&stks, &inst.derivedKQs, &tweaks[0])
		bcTagx1(auth[:], &stks, aStar[:])
	}

	// Message authentication and tag generation.
	msgLen := len(msg)
	for j = 0; msgLen >= 2*api.BlockSize; j += 2 {
		api.EncodeTagTweak(&tweaks[0], api.PrefixMsgBlock, j)
		api.EncodeTagTweak(&tweaks[1], api.PrefixMsgBlock, j+1)

		deriveSubTweakKeysx2(&stks, &inst.derivedKQs, &tweaks)
		bcTagx2(auth[:], &stks, msg[j*api.BlockSize:])
		msgLen -= 2 * api.BlockSize
	}
	for ; msgLen >= api.BlockSize; j++ {
		api.EncodeTagTweak(&tweaks[0], api.PrefixMsgBlock, j)

		deriveSubTweakKeysx1(&stks, &inst.derivedKQs, &tweaks[0])
		bcTagx1(auth[:], &stks, msg[j*api.BlockSize:])
		msgLen -= api.BlockSize
	}
	if msgLen > 0 {
		api.EncodeTagTweak(&tweaks[0], api.PrefixMsgFinal, j)

		var mStar [api.BlockSize]byte
		copy(mStar[:], msg[len(msg)-msgLen:])
		mStar[msgLen] = 0x80

		deriveSubTweakKeysx1(&stks, &inst.derivedKQs, &tweaks[0])
		bcTagx1(auth[:], &stks, mStar[:])
	}

	// Generate the tag.
	var encNonce [api.BlockSize]byte
	copy(encNonce[1:], nonce)
	encNonce[0] = api.PrefixTag << api.PrefixShift
	deriveSubTweakKeysx1(&stks, &inst.derivedKQs, &encNonce)
	bcEncrypt(auth[:], &stks, auth[:])

	// Message encryption.
	encNonce[0] = 0 // 0x00 || nonce

	var encBlks [2 * api.BlockSize]byte
	c := dst[0:]
	msgLen = len(msg)
	for j = 0; msgLen >= 2*api.BlockSize; j += 2 {
		api.EncodeEncTweak(&tweaks[0], auth[:], j)
		api.EncodeEncTweak(&tweaks[1], auth[:], j+1)

		deriveSubTweakKeysx2(&stks, &inst.derivedKQs, &tweaks)
		bcKeystreamx2(encBlks[:], &stks, &encNonce)
		api.XORBytes(c[j*api.BlockSize:], msg[j*api.BlockSize:], encBlks[:], len(encBlks))
		msgLen -= 2 * api.BlockSize
	}
	for ; msgLen >= api.BlockSize; j++ {
		api.EncodeEncTweak(&tweaks[0], auth[:], j)

		deriveSubTweakKeysx1(&stks, &inst.derivedKQs, &tweaks[0])
		bcEncrypt(encBlks[:api.BlockSize], &stks, encNonce[:])
		api.XORBytes(c[j*api.BlockSize:], msg[j*api.BlockSize:], encBlks[:api.BlockSize], api.BlockSize)
		msgLen -= api.BlockSize
	}
	if msgLen > 0 {
		api.EncodeEncTweak(&tweaks[0], auth[:], j)

		deriveSubTweakKeysx1(&stks, &inst.derivedKQs, &tweaks[0])
		bcEncrypt(encBlks[:api.BlockSize], &stks, encNonce[:])
		api.XORBytes(c[j*api.BlockSize:], msg[j*api.BlockSize:], encBlks[:api.BlockSize], msgLen)
	}

	// Append the tag.
	copy(dst[len(dst)-api.TagSize:], auth[:])
}

func (inst *ct32Instance) D(nonce, dst, ad, ct []byte) bool {
	// Split out ct into ciphertext and tag.
	ctLen := len(ct) - api.TagSize
	ciphertext, tag := ct[:ctLen], ct[ctLen:]

	var (
		stks     [api.STKCount][8]uint32
		tweaks   [2][api.TweakSize]byte
		decNonce [api.BlockSize]byte
		j        int
	)

	// Message decryption.
	copy(decNonce[1:], nonce)
	var decTweaks [2][api.TweakSize]byte
	var decBlks [2 * api.BlockSize]byte
	for j = 0; ctLen >= 2*api.BlockSize; j += 2 {
		api.EncodeEncTweak(&decTweaks[0], tag, j)
		api.EncodeEncTweak(&decTweaks[1], tag, j+1)

		deriveSubTweakKeysx2(&stks, &inst.derivedKQs, &decTweaks)
		bcKeystreamx2(decBlks[:], &stks, &decNonce)
		api.XORBytes(dst[j*api.BlockSize:], ciphertext[j*api.BlockSize:], decBlks[:], len(decBlks))
		ctLen -= 2 * api.BlockSize
	}
	for ; ctLen >= api.BlockSize; j++ {
		api.EncodeEncTweak(&decTweaks[0], tag, j)

		deriveSubTweakKeysx1(&stks, &inst.derivedKQs, &decTweaks[0])
		bcEncrypt(decBlks[:api.BlockSize], &stks, decNonce[:])
		api.XORBytes(dst[j*api.BlockSize:], ciphertext[j*api.BlockSize:], decBlks[:api.BlockSize], api.BlockSize)
		ctLen -= api.BlockSize
	}
	if ctLen > 0 {
		api.EncodeEncTweak(&decTweaks[0], tag, j)

		deriveSubTweakKeysx1(&stks, &inst.derivedKQs, &decTweaks[0])
		bcEncrypt(decBlks[:api.BlockSize], &stks, decNonce[:])
		api.XORBytes(dst[j*api.BlockSize:], ciphertext[j*api.BlockSize:], decBlks[:api.BlockSize], ctLen)
	}

	// Associated data.
	adLen := len(ad)
	var (
		auth [api.TagSize]byte
		i    int
	)
	for i = 0; adLen >= 2*api.BlockSize; i += 2 {
		api.EncodeTagTweak(&tweaks[0], api.PrefixADBlock, i)
		api.EncodeTagTweak(&tweaks[1], api.PrefixADBlock, i+1)

		deriveSubTweakKeysx2(&stks, &inst.derivedKQs, &tweaks)
		bcTagx2(auth[:], &stks, ad[i*api.BlockSize:])
		adLen -= 2 * api.BlockSize
	}
	for ; adLen >= api.BlockSize; i++ {
		api.EncodeTagTweak(&tweaks[0], api.PrefixADBlock, i)

		deriveSubTweakKeysx1(&stks, &inst.derivedKQs, &tweaks[0])
		bcTagx1(auth[:], &stks, ad[i*api.BlockSize:])
		adLen -= api.BlockSize
	}
	if adLen > 0 {
		api.EncodeTagTweak(&tweaks[0], api.PrefixADFinal, i)

		var aStar [api.BlockSize]byte
		copy(aStar[:], ad[len(ad)-adLen:])
		aStar[adLen] = 0x80

		deriveSubTweakKeysx1(&stks, &inst.derivedKQs, &tweaks[0])
		bcTagx1(auth[:], &stks, aStar[:])
	}

	// Message authentication and tag generation.
	msgLen := len(dst)
	for j = 0; msgLen >= 2*api.BlockSize; j += 2 {
		api.EncodeTagTweak(&tweaks[0], api.PrefixMsgBlock, j)
		api.EncodeTagTweak(&tweaks[1], api.PrefixMsgBlock, j+1)

		deriveSubTweakKeysx2(&stks, &inst.derivedKQs, &tweaks)
		bcTagx2(auth[:], &stks, dst[j*api.BlockSize:])
		msgLen -= 2 * api.BlockSize
	}
	for ; msgLen >= api.BlockSize; j++ {
		api.EncodeTagTweak(&tweaks[0], api.PrefixMsgBlock, j)

		deriveSubTweakKeysx1(&stks, &inst.derivedKQs, &tweaks[0])
		bcTagx1(auth[:], &stks, dst[j*api.BlockSize:])
		msgLen -= api.BlockSize
	}
	if msgLen > 0 {
		api.EncodeTagTweak(&tweaks[0], api.PrefixMsgFinal, j)

		var mStar [api.BlockSize]byte
		copy(mStar[:], dst[len(dst)-msgLen:])
		mStar[msgLen] = 0x80

		deriveSubTweakKeysx1(&stks, &inst.derivedKQs, &tweaks[0])
		bcTagx1(auth[:], &stks, mStar[:])
	}

	// Generate the re-calculated tag.
	decNonce[0] = api.PrefixTag << api.PrefixShift
	deriveSubTweakKeysx1(&stks, &inst.derivedKQs, &decNonce)
	bcEncrypt(auth[:], &stks, auth[:])

	// Tag verification.
	return subtle.ConstantTimeCompare(tag, auth[:]) == 1
}
