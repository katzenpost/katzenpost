//go:build fuzz

// SPDX-License-Identifier: AGPL-3.0-only

package hpqcfuzz

import (
	"testing"

	"github.com/katzenpost/katzenpost/fuzz/seed"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/hybrid"
	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/nike/x448"
	"github.com/katzenpost/hpqc/rand"
)

func FuzzNIKEUntrustedInput(f *testing.F) {
	schemes := []nike.Scheme{
		x25519.Scheme(rand.Reader),
		x448.Scheme(rand.Reader),
		hybrid.CTIDH512X25519,
	}
	privs := make([]nike.PrivateKey, len(schemes))
	for i, s := range schemes {
		_, priv, err := s.GenerateKeyPair()
		if err != nil {
			f.Fatal(err)
		}
		privs[i] = priv
	}
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add(make([]byte, 32))
	for _, s := range schemes {
		f.Add(make([]byte, s.PublicKeySize()))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if seed.Export(data) {
			return
		}
		for i, s := range schemes {
			pub, err := s.UnmarshalBinaryPublicKey(data)
			if err != nil {
				continue
			}
			_ = s.DeriveSecret(privs[i], pub)
		}
	})
}
