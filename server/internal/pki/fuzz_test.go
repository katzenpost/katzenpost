//go:build fuzz

// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"testing"

	"github.com/katzenpost/katzenpost/fuzz/seed"

	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/server/internal/pkicache"
)

func FuzzDocumentCacheIngest(f *testing.F) {
	scheme := signSchemes.ByName("Ed25519")
	idPub, _, err := scheme.GenerateKey()
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Add([]byte("not-a-document"))
	f.Add(make([]byte, 512))
	f.Fuzz(func(t *testing.T, data []byte) {
		if seed.Export(data) {
			return
		}
		doc, err := cpki.ParseDocument(data)
		if err != nil {
			return
		}
		if err := cpki.IsDocumentWellFormed(doc, nil); err != nil {
			return
		}
		_, _ = pkicache.New(doc, idPub, false, false)
		_, _ = pkicache.New(doc, idPub, true, false)
		_, _ = pkicache.New(doc, idPub, false, true)
	})
}
