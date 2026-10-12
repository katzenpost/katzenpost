// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/pigeonhole"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

func TestReadBeforeWritePollServesTheOtherReplicasSuccess(t *testing.T) {
	courier := createTestCourier(t)

	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	envelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: [2]uint8{2, 0},
		ReplyIndex:           0,
		Epoch:                replicaEpoch,
		SenderPubkey:         []byte("bob-read-before-write-sender-pubkey"),
		Ciphertext:           []byte("bob-read-before-write-ciphertext"),
	}
	envHash := envelope.EnvelopeHash()

	courier.dedupCacheLock.Lock()
	courier.dedupCache[*envHash] = &CourierBookKeeping{
		CreatedAt:            time.Now(),
		IntermediateReplicas: envelope.IntermediateReplicas,
	}
	courier.dedupCacheLock.Unlock()

	notFound := []byte("replica-2-box-id-not-found")
	found := []byte("replica-0-read-repaired-box")
	courier.CacheReply(&commands.ReplicaMessageReply{
		EnvelopeHash:  envHash,
		ReplicaID:     2,
		ErrorCode:     pigeonhole.ReplicaErrorBoxIDNotFound,
		EnvelopeReply: notFound,
	})
	courier.CacheReply(&commands.ReplicaMessageReply{
		EnvelopeHash:  envHash,
		ReplicaID:     0,
		ErrorCode:     pigeonhole.ReplicaSuccess,
		EnvelopeReply: found,
	})

	for poll := 0; poll < 3; poll++ {
		reply := courier.cacheHandleCourierEnvelope(0, envelope)
		require.NotNil(t, reply.EnvelopeReply)
		require.Equal(t, pigeonhole.EnvelopeErrorSuccess, reply.EnvelopeReply.ErrorCode)
		require.Equal(t, found, reply.EnvelopeReply.Payload,
			"poll %d at ReplyIndex 0 was served replica 2's cached BoxIDNotFound although replica 0's success is cached", poll)
		require.Equal(t, uint8(1), reply.EnvelopeReply.ReplyIndex)
	}

	entry, ok := getCacheEntry(courier, *envHash)
	require.True(t, ok)
	require.Zero(t, entry.RedispatchAttempts)
}
