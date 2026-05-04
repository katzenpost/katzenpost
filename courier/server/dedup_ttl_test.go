// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/core/wire/commands"
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
