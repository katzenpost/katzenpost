//go:build fuzz

// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"

	"github.com/katzenpost/katzenpost/fuzz/seed"

	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
)

func FuzzClientDeserialize(f *testing.F) {
	scheme := signSchemes.ByName("Ed25519")
	verifiers := make([]sign.PublicKey, 0, 3)
	for i := 0; i < 3; i++ {
		pub, _, err := scheme.GenerateKey()
		if err != nil {
			f.Fatal(err)
		}
		verifiers = append(verifiers, pub)
	}
	c := &Client{verifiers: verifiers, threshold: 2}

	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Add([]byte("not-a-document"))
	f.Add(make([]byte, 256))
	f.Fuzz(func(t *testing.T, data []byte) {
		if seed.Export(data) {
			return
		}
		doc, err := c.Deserialize(data)
		if err == nil && doc == nil {
			t.Fatal("Deserialize returned nil document and nil error")
		}
	})
}
