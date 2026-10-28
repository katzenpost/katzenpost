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

// TestDedupCacheTTLPruneRemovesStaleEntries verifies that
// pruneDedupCacheLocked removes entries whose age exceeds the TTL while
// leaving fresh entries untouched.
func TestDedupCacheTTLPruneRemovesStaleEntries(t *testing.T) {
	courier := createTestCourier(t)
	now := time.Now()

	staleHash := createTestEnvelopeHashWithSuffix("A")
	freshHash := createTestEnvelopeHashWithSuffix("B")
	borderHash := createTestEnvelopeHashWithSuffix("C")

	courier.dedupCacheLock.Lock()
	courier.dedupCache[staleHash] = &CourierBookKeeping{
		CreatedAt:            now.Add(-2 * DedupCacheTTL),
		IntermediateReplicas: [2]uint8{0, 1},
	}
	courier.dedupCache[freshHash] = &CourierBookKeeping{
		CreatedAt:            now,
		IntermediateReplicas: [2]uint8{0, 1},
	}
	// Exactly at TTL — must NOT be pruned (strictly older evictions only).
	courier.dedupCache[borderHash] = &CourierBookKeeping{
		CreatedAt:            now.Add(-DedupCacheTTL),
		IntermediateReplicas: [2]uint8{0, 1},
	}

	pruned := courier.pruneDedupCacheLocked(now, DedupCacheTTL)
	courier.dedupCacheLock.Unlock()

	require.Equal(t, 1, pruned, "exactly one stale entry should be pruned")

	_, stale := getCacheEntry(courier, staleHash)
	require.False(t, stale, "stale entry older than TTL must be evicted")

	_, fresh := getCacheEntry(courier, freshHash)
	require.True(t, fresh, "fresh entry must remain")

	_, border := getCacheEntry(courier, borderHash)
	require.True(t, border, "entry exactly at TTL must not be evicted")
}

// TestDedupCacheTTLPruneEmptyCache verifies the helper is a no-op on an
// empty cache.
func TestDedupCacheTTLPruneEmptyCache(t *testing.T) {
	courier := createTestCourier(t)

	courier.dedupCacheLock.Lock()
	pruned := courier.pruneDedupCacheLocked(time.Now(), DedupCacheTTL)
	courier.dedupCacheLock.Unlock()

	require.Equal(t, 0, pruned)
}

// TestDedupCacheTTLPruneAllStale verifies that every entry is removed when
// all are older than the TTL.
func TestDedupCacheTTLPruneAllStale(t *testing.T) {
	courier := createTestCourier(t)
	now := time.Now()
	stale := now.Add(-2 * DedupCacheTTL)

	hashes := make([][hash.HashSize]byte, 5)
	for i := range hashes {
		hashes[i] = createTestEnvelopeHashWithSuffix(string(rune('P' + i)))
		courier.dedupCacheLock.Lock()
		courier.dedupCache[hashes[i]] = &CourierBookKeeping{
			CreatedAt:            stale,
			IntermediateReplicas: [2]uint8{0, 1},
		}
		courier.dedupCacheLock.Unlock()
	}

	courier.dedupCacheLock.Lock()
	pruned := courier.pruneDedupCacheLocked(now, DedupCacheTTL)
	remaining := len(courier.dedupCache)
	courier.dedupCacheLock.Unlock()

	require.Equal(t, 5, pruned)
	require.Equal(t, 0, remaining)
}

// TestDedupCacheTTLPrunePreservesReplyData verifies that entries newer
// than TTL keep their cached replies intact through a prune cycle.
func TestDedupCacheTTLPrunePreservesReplyData(t *testing.T) {
	courier := createTestCourier(t)
	now := time.Now()

	envHash := createTestEnvelopeHash()
	reply := &commands.ReplicaMessageReply{
		EnvelopeHash:  &envHash,
		ReplicaID:     0,
		ErrorCode:     0,
		EnvelopeReply: []byte("keep-me"),
	}

	courier.dedupCacheLock.Lock()
	courier.dedupCache[envHash] = &CourierBookKeeping{
		CreatedAt:            now,
		IntermediateReplicas: [2]uint8{0, 1},
		EnvelopeReplies:      [2]*commands.ReplicaMessageReply{reply, nil},
	}
	_ = courier.pruneDedupCacheLocked(now, DedupCacheTTL)
	courier.dedupCacheLock.Unlock()

	entry := verifyCacheEntry(t, courier, envHash)
	require.Same(t, reply, entry.EnvelopeReplies[0])
}

// TestDedupCacheTTLPruneRetainsSuccessfulReplies verifies that only a
// successful replica outcome receives the longer, fixed retention period.
func TestDedupCacheTTLPruneRetainsSuccessfulReplies(t *testing.T) {
	courier := createTestCourier(t)
	now := time.Now()

	successHash := createTestEnvelopeHashWithSuffix("A")
	unresolvedHash := createTestEnvelopeHashWithSuffix("B")
	expiredSuccessHash := createTestEnvelopeHashWithSuffix("C")

	courier.dedupCacheLock.Lock()
	courier.dedupCache[successHash] = &CourierBookKeeping{
		CreatedAt:            now.Add(-2 * DedupCacheTTL),
		SuccessfulReplyAt:    now.Add(-DedupCacheTTL),
		IntermediateReplicas: [2]uint8{0, 1},
	}
	courier.dedupCache[unresolvedHash] = &CourierBookKeeping{
		CreatedAt:            now.Add(-2 * DedupCacheTTL),
		IntermediateReplicas: [2]uint8{0, 1},
	}
	courier.dedupCache[expiredSuccessHash] = &CourierBookKeeping{
		CreatedAt:            now.Add(-2 * CopyDedupCacheTTL),
		SuccessfulReplyAt:    now.Add(-CopyDedupCacheTTL - time.Minute),
		IntermediateReplicas: [2]uint8{0, 1},
	}

	pruned := courier.pruneDedupCacheLocked(now, DedupCacheTTL)
	courier.dedupCacheLock.Unlock()

	require.Equal(t, 2, pruned)

	_, retained := getCacheEntry(courier, successHash)
	require.True(t, retained, "successful reply must remain available")

	_, unresolved := getCacheEntry(courier, unresolvedHash)
	require.False(t, unresolved, "unresolved entry must expire from creation")

	_, expired := getCacheEntry(courier, expiredSuccessHash)
	require.False(t, expired, "successful reply must also have a finite lifetime")
}

// TestDedupCacheTTLTwoPhasePoll follows the client lookup path: a late poll
// receives an already successful outcome, but neither it nor a duplicate
// replica reply extends the deadline. A poll after that deadline starts over.
func TestDedupCacheTTLTwoPhasePoll(t *testing.T) {
	courier := createTestCourier(t)
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	envelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1},
		Epoch:                replicaEpoch,
		SenderPubkey:         []byte("late-poll-sender"),
		Ciphertext:           []byte("late-poll-ciphertext"),
	}
	envHash := envelope.EnvelopeHash()
	old := &CourierBookKeeping{
		CreatedAt:            time.Now().Add(-2 * DedupCacheTTL),
		IntermediateReplicas: envelope.IntermediateReplicas,
	}
	courier.dedupCacheLock.Lock()
	courier.dedupCache[*envHash] = old
	courier.dedupCacheLock.Unlock()

	replicaReply := &commands.ReplicaMessageReply{
		EnvelopeHash:  envHash,
		ReplicaID:     0,
		EnvelopeReply: []byte("stored"),
	}
	courier.CacheReply(replicaReply)
	require.False(t, old.SuccessfulReplyAt.IsZero())
	firstSuccessAt := old.SuccessfulReplyAt

	for i := 0; i < 2; i++ {
		poll := courier.cacheHandleCourierEnvelope(0, envelope)
		require.Equal(t, []byte("stored"), poll.EnvelopeReply.Payload)
		entry, ok := getCacheEntry(courier, *envHash)
		require.True(t, ok)
		require.Same(t, old, entry)
	}
	courier.CacheReply(replicaReply)
	require.Equal(t, firstSuccessAt, old.SuccessfulReplyAt)

	courier.dedupCacheLock.Lock()
	old.SuccessfulReplyAt = time.Now().Add(-CopyDedupCacheTTL - time.Minute)
	courier.dedupCacheLock.Unlock()
	// The new-entry path schedules network dispatch; this unit test has no
	// replica connection, so keep the worker halted while checking cache state.
	courier.Stop()
	defer courier.Halt()
	poll := courier.cacheHandleCourierEnvelope(0, envelope)
	require.Equal(t, pigeonhole.ReplyTypeACK, poll.EnvelopeReply.ReplyType)
	entry, ok := getCacheEntry(courier, *envHash)
	require.True(t, ok)
	require.NotSame(t, old, entry)
	require.Zero(t, entry.RedispatchAttempts)
}

// TestDedupCacheTTLExhaustedRedispatchResetsOnPoll ensures a still-polling
// unresolved write can try again after the fixed five-minute TTL.
func TestDedupCacheTTLExhaustedRedispatchResetsOnPoll(t *testing.T) {
	courier := createTestCourier(t)
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	envelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1},
		Epoch:                replicaEpoch,
		SenderPubkey:         []byte("retry-sender"),
		Ciphertext:           []byte("retry-ciphertext"),
	}
	envHash := envelope.EnvelopeHash()
	old := &CourierBookKeeping{
		CreatedAt:            time.Now().Add(-DedupCacheTTL - time.Minute),
		IntermediateReplicas: envelope.IntermediateReplicas,
		RedispatchAttempts:   maxRedispatchAttempts,
	}
	courier.dedupCacheLock.Lock()
	courier.dedupCache[*envHash] = old
	courier.dedupCacheLock.Unlock()

	courier.Stop()
	defer courier.Halt()
	poll := courier.cacheHandleCourierEnvelope(0, envelope)
	require.Equal(t, pigeonhole.ReplyTypeACK, poll.EnvelopeReply.ReplyType)
	entry, ok := getCacheEntry(courier, *envHash)
	require.True(t, ok)
	require.NotSame(t, old, entry)
	require.Zero(t, entry.RedispatchAttempts)
}
