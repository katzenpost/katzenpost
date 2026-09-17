//go:build fuzz

// SPDX-License-Identifier: AGPL-3.0-only

package hpqcfuzz

import (
	"testing"

	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/hpqc/sign/hybrid"
	"github.com/katzenpost/hpqc/sign/mldsa"
	"github.com/katzenpost/hpqc/sign/sphincsplus"
)

func FuzzSignUntrustedInput(f *testing.F) {
	schemes := []sign.Scheme{
		ed25519.Scheme(),
		mldsa.Scheme44(),
		hybrid.MLDSA44Ed25519,
	}
	if s := sign.Scheme(sphincsplus.Scheme()); s != nil {
		schemes = append(schemes, s)
	}
	pubs := make([]sign.PublicKey, len(schemes))
	for i, s := range schemes {
		pub, _, err := s.GenerateKey()
		if err != nil {
			f.Fatal(err)
		}
		pubs[i] = pub
	}
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add(make([]byte, 64))
	for _, s := range schemes {
		f.Add(make([]byte, s.SignatureSize()))
		f.Add(make([]byte, s.PublicKeySize()))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for i, s := range schemes {
			_, _ = s.UnmarshalBinaryPublicKey(data)
			_, _ = s.UnmarshalBinaryPrivateKey(data)
			_ = s.Verify(pubs[i], data, data, nil)
		}
	})
}
