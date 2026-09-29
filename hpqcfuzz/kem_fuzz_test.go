//go:build fuzz

// SPDX-License-Identifier: AGPL-3.0-only

package hpqcfuzz

import (
	"testing"

	"github.com/katzenpost/katzenpost/fuzz/seed"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/adapter"
	"github.com/katzenpost/hpqc/kem/mlkem768"
	"github.com/katzenpost/hpqc/kem/sntrup"
	"github.com/katzenpost/hpqc/kem/xwing"
	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
)

func FuzzKEMUntrustedInput(f *testing.F) {
	schemes := []kem.Scheme{
		adapter.FromNIKE(x25519.Scheme(rand.Reader)),
		sntrup.Scheme(),
		xwing.Scheme(),
		mlkem768.Scheme(),
	}
	privs := make([]kem.PrivateKey, len(schemes))
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
		f.Add(make([]byte, s.CiphertextSize()))
		f.Add(make([]byte, s.PublicKeySize()))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if seed.Export(data) {
			return
		}
		for i, s := range schemes {
			_, _ = s.UnmarshalBinaryPublicKey(data)
			_, _ = s.UnmarshalBinaryPrivateKey(data)
			_, _ = s.Decapsulate(privs[i], data)
		}
	})
}
