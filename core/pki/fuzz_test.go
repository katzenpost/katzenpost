//go:build fuzz

// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"bytes"
	"encoding/binary"
	"github.com/katzenpost/katzenpost/fuzz/seed"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func structuredSeed() []byte { return make([]byte, 512) }

func FuzzParseDocument(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte("not-a-document"))
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if seed.Export(data) {
			return
		}
		doc, err := ParseDocument(data)
		if err == nil && doc == nil {
			t.Fatal("ParseDocument returned nil doc and nil error")
		}
	})
}

func FuzzDocumentUnmarshalCertificate(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Add([]byte("garbage"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if seed.Export(data) {
			return
		}
		d := new(Document)
		_ = d.UnmarshalCertificate(data)
	})
}

func FuzzMixDescriptorUnmarshalBinary(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Add([]byte("garbage"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if seed.Export(data) {
			return
		}
		d := new(MixDescriptor)
		_ = d.UnmarshalBinary(data)
	})
}

func FuzzReplicaDescriptorUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Add([]byte("garbage"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if seed.Export(data) {
			return
		}
		d := new(ReplicaDescriptor)
		_ = d.Unmarshal(data)
	})
}

func FuzzSignedUploadUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Add([]byte("garbage"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if seed.Export(data) {
			return
		}
		s := new(SignedUpload)
		_ = s.Unmarshal(data)
	})
}

func FuzzMixDescriptorStructured(f *testing.F) {
	f.Add(structuredSeed())
	f.Fuzz(func(t *testing.T, data []byte) {
		if seed.Export(data) {
			return
		}
		d := new(MixDescriptor)
		if err := fuzz.NewConsumer(data).GenerateStruct(d); err != nil {
			return
		}
		blob1, err := d.MarshalBinary()
		if err != nil {
			return
		}
		out := new(MixDescriptor)
		if err := out.UnmarshalBinary(blob1); err != nil {
			return
		}
		blob2, err := out.MarshalBinary()
		if err != nil {
			t.Fatalf("re-marshal of decoded descriptor failed: %v", err)
		}
		again := new(MixDescriptor)
		if err := again.UnmarshalBinary(blob2); err != nil {
			t.Fatalf("re-decode of re-marshaled descriptor failed: %v", err)
		}
		blob3, err := again.MarshalBinary()
		if err != nil {
			t.Fatalf("third marshal of descriptor failed: %v", err)
		}
		if !bytes.Equal(blob2, blob3) {
			t.Fatal("MixDescriptor marshal is not idempotent")
		}
		_ = IsDescriptorWellFormed(out, out.Epoch)
	})
}

func FuzzReplicaDescriptorStructured(f *testing.F) {
	f.Add(structuredSeed())
	f.Fuzz(func(t *testing.T, data []byte) {
		if seed.Export(data) {
			return
		}
		d := new(ReplicaDescriptor)
		if err := fuzz.NewConsumer(data).GenerateStruct(d); err != nil {
			return
		}
		blob1, err := d.Marshal()
		if err != nil {
			return
		}
		out := new(ReplicaDescriptor)
		if err := out.Unmarshal(blob1); err != nil {
			return
		}
		blob2, err := out.Marshal()
		if err != nil {
			t.Fatalf("re-marshal of decoded descriptor failed: %v", err)
		}
		again := new(ReplicaDescriptor)
		if err := again.Unmarshal(blob2); err != nil {
			t.Fatalf("re-decode of re-marshaled descriptor failed: %v", err)
		}
		blob3, err := again.Marshal()
		if err != nil {
			t.Fatalf("third marshal of descriptor failed: %v", err)
		}
		if !bytes.Equal(blob2, blob3) {
			t.Fatal("ReplicaDescriptor marshal is not idempotent")
		}
		_ = IsReplicaDescriptorWellFormed(out, out.Epoch)
	})
}

func FuzzDocumentStructured(f *testing.F) {
	f.Add(structuredSeed())
	f.Fuzz(func(t *testing.T, data []byte) {
		if seed.Export(data) {
			return
		}
		d := new(Document)
		if err := fuzz.NewConsumer(data).GenerateStruct(d); err != nil {
			return
		}
		d.Signatures = nil
		blob, err := ccbor.Marshal((*document)(d))
		if err != nil {
			return
		}
		out := new(Document)
		if err := cbor.Unmarshal(blob, (*document)(out)); err != nil {
			return
		}
		_ = IsDocumentWellFormed(out, nil)
	})
}

func FuzzSharedRandomSetCommitAndVerify(f *testing.F) {
	short := make([]byte, 8)
	full := make([]byte, SharedRandomLength)
	f.Add([]byte(nil), []byte(nil))
	f.Add(short, short)
	f.Add(full, full)
	f.Fuzz(func(t *testing.T, commit, reveal []byte) {
		if seed.Export(commit, reveal) {
			return
		}
		s := new(SharedRandom)
		s.SetCommit(commit)
		if len(commit) >= SharedRandomLength {
			if got := s.GetEpoch(); got != binary.BigEndian.Uint64(commit[0:8]) {
				t.Fatalf("SetCommit epoch mismatch: %d", got)
			}
		}
		if s.Verify(reveal) && len(reveal) != SharedRandomLength {
			t.Fatalf("Verify accepted a reveal of length %d", len(reveal))
		}
	})
}

func TestSharedRandomProperties(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	for _, n := range []int{0, 1, 7, 8, SharedRandomLength - 1} {
		s := new(SharedRandom)
		require.NotPanics(func() { s.SetCommit(make([]byte, n)) })
		require.False(s.Verify(make([]byte, SharedRandomLength)),
			"a too-short commit must never verify (len %d)", n)
	}

	const epoch = uint64(0x1122334455667788)
	s := new(SharedRandom)
	commit, err := s.Commit(epoch)
	require.NoError(err)
	require.Len(commit, SharedRandomLength)

	check := new(SharedRandom)
	check.SetCommit(commit)
	require.Equal(epoch, check.GetEpoch())
	require.True(check.Verify(s.Reveal()), "honest reveal must open its own commit")

	bad := make([]byte, SharedRandomLength)
	copy(bad, s.Reveal())
	binary.BigEndian.PutUint64(bad[0:8], epoch+1)
	require.False(check.Verify(bad), "reveal for the wrong epoch must be rejected")
	require.False(check.Verify(s.Reveal()[:SharedRandomLength-1]), "short reveal rejected")
}
