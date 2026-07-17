// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/pigeonhole"
)

// TestHandleOldMessageRidesOutUnservedRead pins the courier read behavior:
// while a read has no servable reply the courier ACKs it so the client keeps
// polling, no matter how long it has been unserved. The courier imposes no
// give-up deadline of its own; the client daemon owns the read ARQ and retries
// uncapped, so an aged unserved read is still ACKed, never turned into a
// terminal PropagationError. A real payload is always returned.
func TestHandleOldMessageRidesOutUnservedRead(t *testing.T) {
	courier := createTestCourier(t)
	envHash := createTestEnvelopeHash()
	setupCacheEntry(courier, envHash, 1)

	courierEnv := &pigeonhole.CourierEnvelope{ReplyIndex: 0}
	entry, _ := getCacheEntry(courier, envHash)

	// Fresh entry, no replies yet: ACK so the client keeps polling.
	entry.CreatedAt = time.Now()
	got := courier.handleOldMessage(entry, &envHash, courierEnv)
	require.NotNil(t, got)
	require.NotNil(t, got.EnvelopeReply)
	require.Equal(t, pigeonhole.ReplyTypeACK, got.EnvelopeReply.ReplyType)
	require.Equal(t, uint8(pigeonhole.EnvelopeErrorSuccess), got.EnvelopeReply.ErrorCode,
		"a fresh unserved read must be ACKed so the client keeps riding out lag")
	require.Equal(t, uint32(0), got.EnvelopeReply.PayloadLen)

	// Same entry aged far past any prior deadline, still no reply: it is
	// STILL ACKed, never a terminal PropagationError. The client's uncapped
	// ARQ, not a courier-side clock, decides when to give up.
	entry.CreatedAt = time.Now().Add(-1 * time.Hour)
	got = courier.handleOldMessage(entry, &envHash, courierEnv)
	require.NotNil(t, got)
	require.NotNil(t, got.EnvelopeReply)
	require.Equal(t, pigeonhole.ReplyTypeACK, got.EnvelopeReply.ReplyType)
	require.Equal(t, uint8(pigeonhole.EnvelopeErrorSuccess), got.EnvelopeReply.ErrorCode,
		"an aged unserved read must still be ACKed, not terminated with a PropagationError")

	// A servable payload is always returned, regardless of age.
	reply := createTestReply(&envHash, 0, "real-box-payload")
	courier.CacheReply(reply)
	got = courier.handleOldMessage(entry, &envHash, courierEnv)
	require.NotNil(t, got)
	require.NotNil(t, got.EnvelopeReply)
	require.Equal(t, pigeonhole.ReplyTypePayload, got.EnvelopeReply.ReplyType)
	require.Equal(t, reply.EnvelopeReply, got.EnvelopeReply.Payload)
	require.Equal(t, uint8(pigeonhole.EnvelopeErrorSuccess), got.EnvelopeReply.ErrorCode)
}
