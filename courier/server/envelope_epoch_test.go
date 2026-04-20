// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/pigeonhole"
)

// TestIsEnvelopeEpochAcceptable pins the ±1 tolerance window that the
// courier applies to CourierEnvelope.Epoch. Also covers the uint64
// underflow edge case at epoch 0 (e.g. a replica that just booted with
// a stale PKI document claiming epoch 0).
func TestIsEnvelopeEpochAcceptable(t *testing.T) {
	tests := []struct {
		name      string
		envelope  uint64
		current   uint64
		expectOK  bool
	}{
		{"exact match", 100, 100, true},
		{"one below current", 99, 100, true},
		{"one above current", 101, 100, true},
		{"two below current (outside window)", 98, 100, false},
		{"two above current (outside window)", 102, 100, false},
		{"far in the past", 1, 100, false},
		{"far in the future", 200, 100, false},

		// Edge cases around zero — no uint64 underflow allowed.
		{"zero == zero", 0, 0, true},
		{"zero vs current=1", 0, 1, true},
		{"one vs current=0 (no underflow)", 1, 0, true},
		{"two vs current=0 (no underflow)", 2, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isEnvelopeEpochAcceptable(tt.envelope, tt.current)
			require.Equal(t, tt.expectOK, got)
		})
	}
}

// TestValidCourierEnvelopeEpochWindowConstant pins the tolerance so a
// refactor can't silently widen or narrow it. The Pigeonhole spec
// (section "Epoch tolerance for CourierEnvelope") ties this to the
// replica's envelope-key retention: replicas load {current-1, current}
// at startup and generate {current+1} via the PKI publisher, so the
// window MUST be 1.
func TestValidCourierEnvelopeEpochWindowConstant(t *testing.T) {
	require.Equal(t, uint64(1), ValidCourierEnvelopeEpochWindow)
}

// TestCacheHandleCourierEnvelopeRejectsStaleEpoch verifies the full
// integration path: a CourierEnvelope whose epoch is outside the
// tolerance window produces an EnvelopeErrorInvalidEpoch reply and
// does NOT touch the dedup cache (which would leak effort on bogus
// envelopes).
func TestCacheHandleCourierEnvelopeRejectsStaleEpoch(t *testing.T) {
	courier := createTestCourier(t)

	// Pick an epoch far below whatever ReplicaNow() returns — safely
	// outside the ±1 window without depending on wall-clock timing.
	envelope := &pigeonhole.CourierEnvelope{
		Epoch:        1,
		SenderPubkey: []byte("stale-sender-pubkey"),
		Ciphertext:   []byte("stale-ciphertext"),
	}
	envHash := envelope.EnvelopeHash()

	reply := courier.cacheHandleCourierEnvelope(0, envelope)
	require.NotNil(t, reply)
	require.NotNil(t, reply.EnvelopeReply)
	require.Equal(t, pigeonhole.EnvelopeErrorInvalidEpoch, reply.EnvelopeReply.ErrorCode,
		"stale-epoch envelope must be rejected with EnvelopeErrorInvalidEpoch")

	// The dedup cache must NOT have been populated: a future client
	// retry with a fresh (in-window) epoch should go through the
	// new-message path, not be blocked by a cached rejection.
	_, cached := getCacheEntry(courier, *envHash)
	require.False(t, cached,
		"rejected envelopes must not populate the dedup cache")
}

// TestCacheHandleCourierEnvelopeRejectsFarFutureEpoch mirrors the
// stale-epoch case for an epoch far in the future (e.g. a malicious
// or time-skewed client).
func TestCacheHandleCourierEnvelopeRejectsFarFutureEpoch(t *testing.T) {
	courier := createTestCourier(t)

	envelope := &pigeonhole.CourierEnvelope{
		// A value so far in the future ReplicaNow() cannot be within 1.
		Epoch:        1 << 40,
		SenderPubkey: []byte("future-sender-pubkey"),
		Ciphertext:   []byte("future-ciphertext"),
	}

	reply := courier.cacheHandleCourierEnvelope(0, envelope)
	require.NotNil(t, reply)
	require.NotNil(t, reply.EnvelopeReply)
	require.Equal(t, pigeonhole.EnvelopeErrorInvalidEpoch, reply.EnvelopeReply.ErrorCode)
}
