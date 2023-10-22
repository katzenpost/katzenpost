// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package utils

import (
	"github.com/go-faster/xor"
	"golang.org/x/crypto/blake2b"
)

func SplitPRF(ss, cct [][]byte) []byte {

	// implement split PRF KEM combiner as:
	//         cct := cct1 || cct2 || cct3 || ...
	//         return H(ss1 || cct) XOR H(ss2, cct) XOR H(ss3, cct)
	//
	// in order to retain IND-CCA2 security
	// as described in KEM Combiners
	// by Federico Giacon, Felix Heuer, and Bertram Poettering
	// https://eprint.iacr.org/2018/024.pdf

	if len(ss) != len(cct) {
		panic("mismatched slices")
	}

	cctcat := []byte{}
	for i := 0; i < len(cct); i++ {
		cctcat = append(cctcat, cct[i]...)
	}

	hashes := make([][]byte, len(ss))
	for i := 0; i < len(ss); i++ {
		h, err := blake2b.New256(nil)
		if err != nil {
			panic(err)
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

func PairSplitPRF(ss1, ss2, cct1, cct2 []byte) []byte {

	// implement split PRF KEM combiner as:
	//
	// func splitPRF(ss1, ss2, cct1, cct2 []byte) []byte {
	//         cct := cct1 || cct2
	//         return H(ss1 || cct) XOR H(ss2, cct)
	// }
	//
	// Which simplifies to:
	//
	// splitPRF := PRF(ss1, cct2) xor PRF(ss2, cct1)
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
