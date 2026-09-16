//go:build fuzz

// SPDX-License-Identifier: AGPL-3.0-only

package cert

import (
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzGetCertified(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Add([]byte("not-a-cert"))
	f.Fuzz(func(t *testing.T, data []byte) {
		certified, errC := GetCertified(data)
		if errC == nil && certified == nil {
			t.Fatal("GetCertified returned nil data and nil error")
		}
		sigs, errS := GetSignatures(data)
		if errS == nil && sigs == nil {
			t.Fatal("GetSignatures returned nil slice and nil error")
		}
		if (errC == nil) != (errS == nil) {
			t.Fatalf("GetCertified/GetSignatures disagree on validity: %v vs %v", errC, errS)
		}
	})
}

func FuzzSignatureUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Add([]byte("garbage"))
	f.Fuzz(func(t *testing.T, data []byte) {
		s := new(Signature)
		_ = s.Unmarshal(data)
	})
}

func FuzzCertificateStructured(f *testing.F) {
	f.Add(make([]byte, 512))
	f.Fuzz(func(t *testing.T, data []byte) {
		c := new(Certificate)
		if err := fuzz.NewConsumer(data).GenerateStruct(c); err != nil {
			return
		}
		blob, err := c.Marshal()
		if err != nil {
			return
		}
		certified, errC := GetCertified(blob)
		if errC == nil && certified == nil {
			t.Fatal("GetCertified returned nil data and nil error")
		}
		sigs, errS := GetSignatures(blob)
		if errS == nil && sigs == nil {
			t.Fatal("GetSignatures returned nil slice and nil error")
		}
		if (errC == nil) != (errS == nil) {
			t.Fatalf("GetCertified/GetSignatures disagree: %v vs %v", errC, errS)
		}
	})
}
