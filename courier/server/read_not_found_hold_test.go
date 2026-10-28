// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/pigeonhole"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// shardReadEntry caches a read sent to shard holders 2 and 0 and returns
// its envelope.
func shardReadEntry(t *testing.T, courier *Courier, createdAt time.Time) (*pigeonhole.CourierEnvelope, *[hash.HashSize]byte) {
	t.Helper()
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	envelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: [2]uint8{2, 0},
		Epoch:                replicaEpoch,
		SenderPubkey:         []byte("shard-read-sender"),
		Ciphertext:           []byte("shard-read-ciphertext"),
	}
	envHash := envelope.EnvelopeHash()
	courier.dedupCacheLock.Lock()
	courier.dedupCache[*envHash] = &CourierBookKeeping{
		CreatedAt:            createdAt,
		IntermediateReplicas: envelope.IntermediateReplicas,
	}
	courier.dedupCacheLock.Unlock()
	return envelope, envHash
}

func cacheReadReply(courier *Courier, envHash *[hash.HashSize]byte, replicaID, errorCode uint8, payload string) {
	courier.CacheReply(&commands.ReplicaMessageReply{
		EnvelopeHash:  envHash,
		ReplicaID:     replicaID,
		ErrorCode:     errorCode,
		EnvelopeReply: []byte(payload),
	})
}

func pollAt(courier *Courier, envelope *pigeonhole.CourierEnvelope, replyIndex uint8) *pigeonhole.CourierEnvelopeReply {
	poll := *envelope
	poll.ReplyIndex = replyIndex
	return courier.cacheHandleCourierEnvelope(0, &poll).EnvelopeReply
}

// TestReadNotFoundBeforeHolderSuccess has one shard holder answer
// box-not-found before the holder that has the box answers. Polls at
// either index are ACKed until the second reply arrives, and then the
// success is served.
func TestReadNotFoundBeforeHolderSuccess(t *testing.T) {
	courier := createTestCourier(t)
	envelope, envHash := shardReadEntry(t, courier, time.Now())

	cacheReadReply(courier, envHash, 2, pigeonhole.ReplicaErrorBoxIDNotFound, "not-found")
	for _, idx := range []uint8{0, 1} {
		reply := pollAt(courier, envelope, idx)
		require.Equal(t, pigeonhole.EnvelopeErrorSuccess, reply.ErrorCode)
		require.Equal(t, pigeonhole.ReplyTypeACK, reply.ReplyType, "poll at %d served box-not-found before the other holder answered", idx)
		require.Empty(t, reply.Payload)
	}

	cacheReadReply(courier, envHash, 0, pigeonhole.ReplicaSuccess, "box")
	for _, idx := range []uint8{0, 1} {
		reply := pollAt(courier, envelope, idx)
		require.Equal(t, pigeonhole.ReplyTypePayload, reply.ReplyType)
		require.Equal(t, []byte("box"), reply.Payload)
		require.Equal(t, uint8(1), reply.ReplyIndex)
	}
}

// TestReadNotFoundFromBothHolders serves box-not-found at once when both
// holders report it.
func TestReadNotFoundFromBothHolders(t *testing.T) {
	courier := createTestCourier(t)
	envelope, envHash := shardReadEntry(t, courier, time.Now())

	cacheReadReply(courier, envHash, 2, pigeonhole.ReplicaErrorBoxIDNotFound, "not-found-2")
	cacheReadReply(courier, envHash, 0, pigeonhole.ReplicaErrorBoxIDNotFound, "not-found-0")
	reply := pollAt(courier, envelope, 0)
	require.Equal(t, pigeonhole.ReplyTypePayload, reply.ReplyType)
	require.Equal(t, []byte("not-found-2"), reply.Payload)
}

// TestReadNotFoundWhenOtherHolderIsSilent serves box-not-found once
// notFoundHoldWindow has passed without an answer from the other holder.
func TestReadNotFoundWhenOtherHolderIsSilent(t *testing.T) {
	courier := createTestCourier(t)
	// The entry is old enough to be redispatched; this test has no
	// replica connections, so keep the worker halted.
	courier.Stop()
	defer courier.Halt()
	envelope, envHash := shardReadEntry(t, courier, time.Now().Add(-notFoundHoldWindow-time.Second))

	cacheReadReply(courier, envHash, 2, pigeonhole.ReplicaErrorBoxIDNotFound, "not-found")
	reply := pollAt(courier, envelope, 1)
	require.Equal(t, pigeonhole.ReplyTypePayload, reply.ReplyType)
	require.Equal(t, []byte("not-found"), reply.Payload)
}
