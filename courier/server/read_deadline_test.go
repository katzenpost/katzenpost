// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/pigeonhole"
)

// TestHandleOldMessageRidesOutThenSurfacesUnservedRead pins the courier
// read-deadline behavior. While a read has no servable reply it is ACKed so
// the client keeps polling (riding out transient replication lag); but once
// the entry has stayed unserved past ReadUnservedDeadline the courier stops
// masking the failure as a success-ACK and returns a PropagationError, so the
// client's read ARQ terminates with a visible error instead of polling a dead
// replica tier forever. A real payload is never overridden by the deadline.
func TestHandleOldMessageRidesOutThenSurfacesUnservedRead(t *testing.T) {
	courier := createTestCourier(t)
	envHash := createTestEnvelopeHash()
	setupCacheEntry(courier, envHash, 1)

	courierEnv := &pigeonhole.CourierEnvelope{ReplyIndex: 0}
	entry, _ := getCacheEntry(courier, envHash)

	// Fresh entry, no replies yet: ride out with an ACK so the client
	// keeps polling.
	entry.CreatedAt = time.Now()
	got := courier.handleOldMessage(entry, &envHash, courierEnv)
	require.NotNil(t, got)
	require.NotNil(t, got.EnvelopeReply)
	require.Equal(t, pigeonhole.ReplyTypeACK, got.EnvelopeReply.ReplyType)
	require.Equal(t, uint8(pigeonhole.EnvelopeErrorSuccess), got.EnvelopeReply.ErrorCode,
		"a fresh unserved read must be ACKed so the client keeps riding out lag")
	require.Equal(t, uint32(0), got.EnvelopeReply.PayloadLen)

	// Same entry aged past the deadline, still no reply: surface a
	// PropagationError so the read ARQ can terminate.
	entry.CreatedAt = time.Now().Add(-ReadUnservedDeadline - time.Second)
	got = courier.handleOldMessage(entry, &envHash, courierEnv)
	require.NotNil(t, got)
	require.NotNil(t, got.EnvelopeReply)
	require.Equal(t, uint8(pigeonhole.EnvelopeErrorPropagationError), got.EnvelopeReply.ErrorCode,
		"an unserved read past the deadline must surface a PropagationError, not a masked success-ACK")

	// A servable payload wins even past the deadline: real data is never
	// overridden by the deadline check.
	reply := createTestReply(&envHash, 0, "real-box-payload")
	courier.CacheReply(reply)
	got = courier.handleOldMessage(entry, &envHash, courierEnv)
	require.NotNil(t, got)
	require.NotNil(t, got.EnvelopeReply)
	require.Equal(t, pigeonhole.ReplyTypePayload, got.EnvelopeReply.ReplyType)
	require.Equal(t, reply.EnvelopeReply, got.EnvelopeReply.Payload)
	require.Equal(t, uint8(pigeonhole.EnvelopeErrorSuccess), got.EnvelopeReply.ErrorCode)
}
