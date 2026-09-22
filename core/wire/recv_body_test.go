package wire

import (
	"bytes"
	"testing"
)

func TestReadCommandBodyExact(t *testing.T) {
	want := bytes.Repeat([]byte{0xab}, recvChunkSize*2+123)
	got, err := readCommandBody(bytes.NewReader(want), len(want))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("body mismatch")
	}
}

// DoS regression: a peer that declares a huge body but sends little must error, not allocate the declared size.
func TestReadCommandBodyTruncated(t *testing.T) {
	const declared = 500 * 1000 * 1000
	sent := bytes.Repeat([]byte{0x01}, recvChunkSize)
	if _, err := readCommandBody(bytes.NewReader(sent), declared); err == nil {
		t.Fatal("expected error for truncated body")
	}
}
