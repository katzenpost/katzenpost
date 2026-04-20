// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/pigeonhole"
)

// TestHandleOldMessageRejectsOutOfRangeReplyIndex pins the invariant
// that a CourierEnvelope with ReplyIndex outside the valid [0, 1]
// range cannot crash the courier. EnvelopeReplies is a 2-element array;
// indexing with any higher value would panic the goroutine that runs
// OnCommand, and ReplyIndex is attacker-controlled (client-supplied).
func TestHandleOldMessageRejectsOutOfRangeReplyIndex(t *testing.T) {
	courier := createTestCourier(t)
	envHash := createTestEnvelopeHash()

	setupCacheEntry(courier, envHash, 1)

	// Populate a reply so the cache entry looks "real"; the test's
	// intent is to exercise the out-of-range guard, not reply lookup.
	reply := createTestReply(&envHash, 0, "valid-cached-reply")
	courier.CacheReply(reply)

	cacheEntry, _ := getCacheEntry(courier, envHash)

	for _, replyIdx := range []uint8{2, 3, 7, 42, 255} {
		courierEnv := &pigeonhole.CourierEnvelope{
			ReplyIndex: replyIdx,
		}

		var got *pigeonhole.CourierQueryReply
		require.NotPanics(t, func() {
			got = courier.handleOldMessage(cacheEntry, &envHash, courierEnv)
		}, "out-of-range ReplyIndex=%d must not panic", replyIdx)

		require.NotNil(t, got)
		require.NotNil(t, got.EnvelopeReply)
		require.NotEqual(t, uint8(pigeonhole.EnvelopeErrorSuccess), got.EnvelopeReply.ErrorCode,
			"ReplyIndex=%d must produce an error envelope reply", replyIdx)
	}
}
