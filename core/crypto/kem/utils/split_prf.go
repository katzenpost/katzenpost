// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package utils

import (
	"github.com/go-faster/xor"
	"golang.org/x/crypto/blake2b"
)

// SplitPRF can be used with any number of KEMs
// and it implement split PRF KEM combiner as:
//
//	cct := cct1 || cct2 || cct3 || ...
//	return H(ss1 || cct) XOR H(ss2 || cct) XOR H(ss3 || cct)
//
// in order to retain IND-CCA2 security
// as described in KEM Combiners  https://eprint.iacr.org/2018/024.pdf
// by Federico Giacon, Felix Heuer, and Bertram Poettering
func SplitPRF(ss, cct [][]byte) []byte {

	if len(ss) != len(cct) {
		panic("mismatched slices")
	}

	cctcat := []byte{}
	for i := 0; i < len(cct); i++ {
		if cct[i] == nil {
			panic("ciphertext cannot be nil")
		}
		if len(cct[i]) == 0 {
			panic("ciphertext cannot be zero length")
		}
		cctcat = append(cctcat, cct[i]...)
	}

	hashes := make([][]byte, len(ss))
	for i := 0; i < len(ss); i++ {
		h, err := blake2b.New256(nil)
		if err != nil {
			panic(err)
		}
		if ss[i] == nil {
			panic("shared secret cannot be nil")
		}
		if len(ss[i]) == 0 {
			panic("shared secret cannot be zero length")
		}
		_, err = h.Write(ss[i])
		if err != nil {
			panic(err)
		}
		_, err = h.Write(cctcat)
		if err != nil {
			panic(err)
		}
		hashes[i] = h.Sum(nil)
	}

	acc := hashes[0]
	for i := 1; i < len(ss); i++ {
		out := make([]byte, 32)
		xor.Bytes(out, acc, hashes[i])
		acc = out
	}
	return acc
}

// PairSplitPRF is a split PRF that operates on only two KEMs.
func PairSplitPRF(ss1, ss2, cct1, cct2 []byte) []byte {
	return SplitPRF([][]byte{ss1, ss2}, [][]byte{cct1, cct2})
}

// This is a simplified split PRF construction
// that only works for combining two KEMs. If we
// were to use this it would make our hybrid KEM combiner
// NOT binary compatible with our multi KEM combiner when
// it's combinging only two KEMs.
// Keeping it here for posterity and just in case we only want
// to combiner two KEMs we could just use this and get rid of
// the other combiner. That's one possible future route to take.
func nopePairSplitPRF(ss1, ss2, cct1, cct2 []byte) []byte {

	// implement split PRF KEM combiner as:
	//
	// func splitPRF(ss1, ss2, cct1, cct2 []byte) []byte {
	//         cct := cct1 || cct2
	//         return H(ss1 || cct) XOR H(ss2 || cct)
	// }
	//
	// Which simplifies to:
	//
	// splitPRF := PRF(ss1 || cct2) XOR PRF(ss2 || cct1)
	//
	// in order to retain IND-CCA2 security
	// as described in KEM Combiners
	// by Federico Giacon, Felix Heuer, and Bertram Poettering
	// https://eprint.iacr.org/2018/024.pdf
	//

	h1, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	_, err = h1.Write(ss1)
	if err != nil {
		panic(err)
	}
	_, err = h1.Write(cct2)
	if err != nil {
		panic(err)
	}
	hash1 := h1.Sum(nil)

	h2, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	_, err = h2.Write(ss2)
	if err != nil {
		panic(err)
	}
	_, err = h2.Write(cct1)
	if err != nil {
		panic(err)
	}
	hash2 := h2.Sum(nil)

	out := make([]byte, len(hash1))
	xor.Bytes(out, hash1, hash2)
	return out
}
