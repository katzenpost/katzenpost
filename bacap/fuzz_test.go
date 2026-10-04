//go:build fuzz

// SPDX-License-Identifier: AGPL-3.0-only

package bacapfuzz

import (
	"bytes"
	"testing"

	"github.com/katzenpost/katzenpost/fuzz/seed"

	"github.com/katzenpost/hpqc/bacap"
)

func FuzzWriteCapFromBytes(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add(make([]byte, bacap.WriteCapSize))
	f.Fuzz(func(t *testing.T, data []byte) {
		if seed.Export(data) {
			return
		}
		wc, err := bacap.NewWriteCapFromBytes(data)
		if err != nil {
			return
		}
		if wc == nil {
			t.Fatal("NewWriteCapFromBytes returned nil cap and nil error")
		}
		blob, err := wc.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary of parsed WriteCap failed: %v", err)
		}
		if !bytes.Equal(blob, data) {
			t.Fatal("WriteCap re-marshal is not idempotent")
		}
	})
}

func FuzzReadCapFromBytes(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add(make([]byte, bacap.ReadCapSize))
	f.Fuzz(func(t *testing.T, data []byte) {
		if seed.Export(data) {
			return
		}
		rc, err := bacap.ReadCapFromBytes(data)
		if err != nil {
			return
		}
		if rc == nil {
			t.Fatal("ReadCapFromBytes returned nil cap and nil error")
		}
		blob, err := rc.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary of parsed ReadCap failed: %v", err)
		}
		if !bytes.Equal(blob, data) {
			t.Fatal("ReadCap re-marshal is not idempotent")
		}
	})
}

func FuzzMessageBoxIndexUnmarshal(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add(make([]byte, bacap.MessageBoxIndexSize))
	f.Fuzz(func(t *testing.T, data []byte) {
		if seed.Export(data) {
			return
		}
		idx := new(bacap.MessageBoxIndex)
		if err := idx.UnmarshalBinary(data); err != nil {
			return
		}
		blob, err := idx.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary of parsed MessageBoxIndex failed: %v", err)
		}
		if !bytes.Equal(blob, data) {
			t.Fatal("MessageBoxIndex re-marshal is not idempotent")
		}
	})
}

func FuzzReadCapIndexBoxID(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add(make([]byte, bacap.ReadCapSize+bacap.MessageBoxIndexSize))
	f.Fuzz(func(t *testing.T, data []byte) {
		if seed.Export(data) {
			return
		}
		if len(data) < bacap.ReadCapSize+bacap.MessageBoxIndexSize {
			return
		}
		rc, err := bacap.ReadCapFromBytes(data[:bacap.ReadCapSize])
		if err != nil {
			return
		}
		idx, err := bacap.NewEmptyMessageBoxIndexFromBytes(data[bacap.ReadCapSize : bacap.ReadCapSize+bacap.MessageBoxIndexSize])
		if err != nil {
			return
		}
		_, _ = idx.BoxIDForContext(rc, []byte("pigeonhole context"))
	})
}
