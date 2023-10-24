//SPDX-FileCopyrightText: (C) 2023  David Stainton.
//SPDX-License-Identifier: AGPL-3.0-only

package schemes

import (
	"bytes"
	"testing"
)

func BenchmarkHybridKyberKEMEncap(b *testing.B) {
	s := ByName("Kyber768-X25519")
	pubkey, privkey, err := s.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	ct := []byte{}
	ss := []byte{}

	for n := 0; n < b.N; n++ {
		ct, ss, err = s.Encapsulate(pubkey)
		if err != nil {
			panic(err)
		}
	}

	ss2, err := s.Decapsulate(privkey, ct)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(ss, ss2) {
		panic("wtf")
	}
}

func BenchmarkHybridKyberKEMDecap(b *testing.B) {
	s := ByName("Kyber768-X25519")
	pubkey, privkey, err := s.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	ct, ss, err := s.Encapsulate(pubkey)
	if err != nil {
		panic(err)
	}

	ss2 := []byte{}
	for n := 0; n < b.N; n++ {
		ss2, err = s.Decapsulate(privkey, ct)
		if err != nil {
			panic(err)
		}
	}

	if !bytes.Equal(ss, ss2) {
		panic("wtf")
	}
}

func BenchmarkHybridMcElieceKEMEncap(b *testing.B) {
	s := ByName("McEliece-X25519")
	pubkey, privkey, err := s.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	ct := []byte{}
	ss := []byte{}

	for n := 0; n < b.N; n++ {
		ct, ss, err = s.Encapsulate(pubkey)
		if err != nil {
			panic(err)
		}
	}

	ss2, err := s.Decapsulate(privkey, ct)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(ss, ss2) {
		panic("wtf")
	}
}

func BenchmarkHybridMcElieceKEMDecap(b *testing.B) {
	s := ByName("McEliece-X25519")
	pubkey, privkey, err := s.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	ct, ss, err := s.Encapsulate(pubkey)
	if err != nil {
		panic(err)
	}

	ss2 := []byte{}
	for n := 0; n < b.N; n++ {
		ss2, err = s.Decapsulate(privkey, ct)
		if err != nil {
			panic(err)
		}
	}

	if !bytes.Equal(ss, ss2) {
		panic("wtf")
	}
}
