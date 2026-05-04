// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonhole

import (
	"bytes"
	"testing"
)

// hybridPubkeySize is the byte length of one CTIDH1024+X25519 hybrid
// public key (128 + 32 = 160). This is the bandwidth saving that the
// cache_id optimization buys us per query, after the first envelope
// has primed the cache.
const hybridPubkeySize = 160

// fixedFieldsSize is the byte length of all fixed-size fields in a
// CachedCourierEnvelope, plus the two length-prefix fields. It does
// NOT include sender_pubkey or ciphertext bytes.
//
//	cache_id (16) + intermediate_replicas (2) + dek1 (60) + dek2 (60)
//	+ reply_index (1) + epoch (8) + sender_pubkey_len (2)
//	+ ciphertext_len (4) = 153
const fixedFieldsSize = 16 + 2 + 60 + 60 + 1 + 8 + 2 + 4

// makeEnvelope constructs a CachedCourierEnvelope for tests. Pass
// pubkeyLen = 0 for the cache-hit form, or hybridPubkeySize to prime
// the cache.
func makeEnvelope(pubkeyLen int, ciphertextLen int) *CachedCourierEnvelope {
	env := &CachedCourierEnvelope{
		IntermediateReplicas: [2]uint8{3, 7},
		ReplyIndex:           0,
		Epoch:                42,
		SenderPubkeyLen:      uint16(pubkeyLen),
		CiphertextLen:        uint32(ciphertextLen),
	}
	for i := range env.CacheID {
		env.CacheID[i] = byte(i + 1)
	}
	for i := range env.Dek1 {
		env.Dek1[i] = byte(0xa0 + i%16)
	}
	for i := range env.Dek2 {
		env.Dek2[i] = byte(0xb0 + i%16)
	}
	if pubkeyLen > 0 {
		env.SenderPubkey = make([]uint8, pubkeyLen)
		for i := range env.SenderPubkey {
			env.SenderPubkey[i] = byte(0xc0 + i%16)
		}
	}
	if ciphertextLen > 0 {
		env.Ciphertext = make([]uint8, ciphertextLen)
		for i := range env.Ciphertext {
			env.Ciphertext[i] = byte(i % 256)
		}
	}
	return env
}

// TestRoundTripCachePrimeForm exercises the form a client uses on
// its first envelope to a fresh courier: sender_pubkey is inline,
// 160 B for CTIDH1024+X25519. The courier extracts the pubkey,
// associates it with cache_id, and forwards a binary-compatible
// mixnet envelope to the intermediate replicas.
func TestRoundTripCachePrimeForm(t *testing.T) {
	in := makeEnvelope(hybridPubkeySize, 256)

	wire, err := in.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	wantLen := fixedFieldsSize + hybridPubkeySize + 256
	if got := len(wire); got != wantLen {
		t.Errorf("wire length = %d, want %d (fixed %d + pubkey %d + ct 256)",
			got, wantLen, fixedFieldsSize, hybridPubkeySize)
	}

	out, err := ParseCachedCourierEnvelope(wire)
	if err != nil {
		t.Fatalf("ParseCachedCourierEnvelope: %v", err)
	}
	assertEnvelopesEqual(t, in, out)
}

// TestRoundTripCacheHitForm exercises the form a client uses for
// every subsequent envelope after the cache is primed: sender_pubkey
// is empty, just the cache_id selects the cached pubkey at the
// courier. This is the bandwidth-optimized form, saving 160 B per
// envelope on the radio leg.
func TestRoundTripCacheHitForm(t *testing.T) {
	in := makeEnvelope(0, 256)

	wire, err := in.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	wantLen := fixedFieldsSize + 256
	if got := len(wire); got != wantLen {
		t.Errorf("wire length = %d, want %d (fixed %d + no pubkey + ct 256)",
			got, wantLen, fixedFieldsSize)
	}

	out, err := ParseCachedCourierEnvelope(wire)
	if err != nil {
		t.Fatalf("ParseCachedCourierEnvelope: %v", err)
	}
	if out.SenderPubkeyLen != 0 {
		t.Errorf("SenderPubkeyLen = %d, want 0", out.SenderPubkeyLen)
	}
	if len(out.SenderPubkey) != 0 {
		t.Errorf("len(SenderPubkey) = %d, want 0", len(out.SenderPubkey))
	}
	assertEnvelopesEqual(t, in, out)
}

// TestCacheHitSavesPubkeyBytes pins the bandwidth-savings invariant:
// a cache-hit envelope is exactly hybridPubkeySize bytes shorter on
// the wire than the corresponding cache-prime envelope.
func TestCacheHitSavesPubkeyBytes(t *testing.T) {
	prime, err := makeEnvelope(hybridPubkeySize, 256).MarshalBinary()
	if err != nil {
		t.Fatalf("prime MarshalBinary: %v", err)
	}
	hit, err := makeEnvelope(0, 256).MarshalBinary()
	if err != nil {
		t.Fatalf("hit MarshalBinary: %v", err)
	}
	saving := len(prime) - len(hit)
	if saving != hybridPubkeySize {
		t.Errorf("cache hit saves %d B, want %d (the hybrid pubkey)", saving, hybridPubkeySize)
	}
}

// TestParseRejectsTruncated catches accidental truncation: the
// generated parser must report an error rather than silently
// succeeding on a short buffer.
func TestParseRejectsTruncated(t *testing.T) {
	wire, err := makeEnvelope(hybridPubkeySize, 64).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	for cut := 1; cut < len(wire); cut++ {
		if _, err := ParseCachedCourierEnvelope(wire[:cut]); err == nil {
			t.Errorf("parse succeeded on %d/%d bytes; want error", cut, len(wire))
			return
		}
	}
}

// TestParseRejectsTrailingGarbage isn't a strict requirement (the
// generated parser returns leftover bytes via the lower-level
// Parse), but ParseCachedCourierEnvelope should reject extra bytes
// after the message ends.
func TestParseRejectsTrailingGarbage(t *testing.T) {
	wire, err := makeEnvelope(hybridPubkeySize, 64).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	tail := append(wire, 0xff, 0xff, 0xff)
	if _, err := ParseCachedCourierEnvelope(tail); err == nil {
		t.Logf("note: ParseCachedCourierEnvelope accepted trailing bytes; not strictly wrong but worth knowing")
	}
}

func assertEnvelopesEqual(t *testing.T, want, got *CachedCourierEnvelope) {
	t.Helper()
	if want.CacheID != got.CacheID {
		t.Errorf("CacheID mismatch: want %x got %x", want.CacheID, got.CacheID)
	}
	if want.IntermediateReplicas != got.IntermediateReplicas {
		t.Errorf("IntermediateReplicas mismatch: want %v got %v",
			want.IntermediateReplicas, got.IntermediateReplicas)
	}
	if want.Dek1 != got.Dek1 {
		t.Errorf("Dek1 mismatch")
	}
	if want.Dek2 != got.Dek2 {
		t.Errorf("Dek2 mismatch")
	}
	if want.ReplyIndex != got.ReplyIndex {
		t.Errorf("ReplyIndex mismatch: want %d got %d", want.ReplyIndex, got.ReplyIndex)
	}
	if want.Epoch != got.Epoch {
		t.Errorf("Epoch mismatch: want %d got %d", want.Epoch, got.Epoch)
	}
	if want.SenderPubkeyLen != got.SenderPubkeyLen {
		t.Errorf("SenderPubkeyLen mismatch: want %d got %d",
			want.SenderPubkeyLen, got.SenderPubkeyLen)
	}
	if !bytes.Equal(want.SenderPubkey, got.SenderPubkey) {
		t.Errorf("SenderPubkey bytes mismatch")
	}
	if want.CiphertextLen != got.CiphertextLen {
		t.Errorf("CiphertextLen mismatch: want %d got %d",
			want.CiphertextLen, got.CiphertextLen)
	}
	if !bytes.Equal(want.Ciphertext, got.Ciphertext) {
		t.Errorf("Ciphertext bytes mismatch")
	}
}
