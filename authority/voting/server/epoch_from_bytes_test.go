// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"encoding/binary"
	"testing"
)

func TestEpochFromBytes(t *testing.T) {
	if got := epochFromBytes(nil); got != 0 {
		t.Fatalf("nil: got %d, want 0", got)
	}
	if got := epochFromBytes([]byte{1, 2, 3}); got != 0 {
		t.Fatalf("short: got %d, want 0", got)
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], 42)
	if got := epochFromBytes(b[:]); got != 42 {
		t.Fatalf("valid: got %d, want 42", got)
	}
}
