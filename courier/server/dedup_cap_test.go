// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/courier/server/config"
	"github.com/katzenpost/katzenpost/pigeonhole"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// newCappedTestCourier returns a test courier whose dedup cache holds at
// most limit entries. Its worker is stopped so new entries schedule no
// replica traffic; the caller must defer Halt.
func newCappedTestCourier(t *testing.T, limit int) *Courier {
	t.Helper()
	courier := createTestCourier(t)
	courier.maxDedupCacheEntries = limit
	courier.Stop()
	return courier
}

func capTestEnvelope(name string) *pigeonhole.CourierEnvelope {
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	return &pigeonhole.CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1},
		Epoch:                replicaEpoch,
		SenderPubkey:         []byte("cap-sender"),
		Ciphertext:           []byte(name),
	}
}

// insertEnvelope sends a new envelope through the client path and
// requires that the courier accepted it.
func insertEnvelope(t *testing.T, courier *Courier, name string) *[hash.HashSize]byte {
	t.Helper()
	envelope := capTestEnvelope(name)
	reply := courier.cacheHandleCourierEnvelope(0, envelope)
	require.Equal(t, pigeonhole.EnvelopeErrorSuccess, reply.EnvelopeReply.ErrorCode, "envelope %s refused", name)
	require.Equal(t, pigeonhole.ReplyTypeACK, reply.EnvelopeReply.ReplyType)
	return envelope.EnvelopeHash()
}

// markSuccessful caches a successful replica reply for envHash and then
// pins its SuccessfulReplyAt so eviction order does not depend on clock
// resolution.
func markSuccessful(t *testing.T, courier *Courier, envHash *[hash.HashSize]byte, at time.Time) {
	t.Helper()
	courier.CacheReply(&commands.ReplicaMessageReply{
		EnvelopeHash:  envHash,
		ReplicaID:     0,
		EnvelopeReply: []byte("stored"),
	})
	courier.dedupCacheLock.Lock()
	defer courier.dedupCacheLock.Unlock()
	entry := courier.dedupCache[*envHash]
	require.NotNil(t, entry)
	require.False(t, entry.SuccessfulReplyAt.IsZero())
	entry.SuccessfulReplyAt = at
}

// allowSweep lets the next insert scan the cache, as if
// dedupSweepInterval had passed since the last scan.
func allowSweep(courier *Courier) {
	courier.dedupCacheLock.Lock()
	courier.lastDedupSweep = time.Time{}
	courier.dedupCacheLock.Unlock()
}

func dedupCacheLen(courier *Courier) int {
	courier.dedupCacheLock.Lock()
	defer courier.dedupCacheLock.Unlock()
	return len(courier.dedupCache)
}

func TestDedupCacheCapDefault(t *testing.T) {
	courier := createTestCourier(t)
	require.Equal(t, config.DefaultMaxDedupCacheEntries, courier.maxDedupCacheEntries)

	courier.server.cfg.MaxDedupCacheEntries = 7
	courier = NewCourier(courier.server, courier.cmds, courier.envelopeScheme)
	require.Equal(t, 7, courier.maxDedupCacheEntries)
}

func TestDedupCacheCapRemovesExpiredFirst(t *testing.T) {
	courier := newCappedTestCourier(t, 10)
	defer courier.Halt()

	var expired, successful [][hash.HashSize]byte
	for i := 0; i < 5; i++ {
		expired = append(expired, *insertEnvelope(t, courier, fmt.Sprintf("expired-%d", i)))
	}
	now := time.Now()
	for i := 0; i < 5; i++ {
		h := insertEnvelope(t, courier, fmt.Sprintf("successful-%d", i))
		markSuccessful(t, courier, h, now.Add(-time.Duration(5-i)*time.Minute))
		successful = append(successful, *h)
	}
	courier.dedupCacheLock.Lock()
	for _, h := range expired {
		courier.dedupCache[h].CreatedAt = now.Add(-2 * DedupCacheTTL)
	}
	courier.dedupCacheLock.Unlock()
	require.Equal(t, 10, dedupCacheLen(courier))

	allowSweep(courier)
	newHash := insertEnvelope(t, courier, "new")

	for _, h := range expired {
		_, ok := getCacheEntry(courier, h)
		require.False(t, ok, "expired entry must be removed")
	}
	for _, h := range successful {
		_, ok := getCacheEntry(courier, h)
		require.True(t, ok, "successful entry must stay while expired entries free enough room")
	}
	_, ok := getCacheEntry(courier, *newHash)
	require.True(t, ok)
	require.Equal(t, 6, dedupCacheLen(courier))
}

func TestDedupCacheCapEvictsOldestSuccessful(t *testing.T) {
	// A cap of 20 makes the eviction batch two entries.
	courier := newCappedTestCourier(t, 20)
	defer courier.Halt()

	var unresolved [][hash.HashSize]byte
	for i := 0; i < 16; i++ {
		unresolved = append(unresolved, *insertEnvelope(t, courier, fmt.Sprintf("unresolved-%d", i)))
	}
	now := time.Now()
	successful := make([][hash.HashSize]byte, 4)
	// Mark them out of insertion order so eviction must sort by
	// SuccessfulReplyAt: successful[0] is the oldest.
	for _, i := range []int{2, 0, 3, 1} {
		h := insertEnvelope(t, courier, fmt.Sprintf("successful-%d", i))
		markSuccessful(t, courier, h, now.Add(-time.Duration(10-i)*time.Minute))
		successful[i] = *h
	}
	require.Equal(t, 20, dedupCacheLen(courier))

	allowSweep(courier)
	newHash := insertEnvelope(t, courier, "new")

	for i, h := range successful {
		_, ok := getCacheEntry(courier, h)
		require.Equal(t, i >= 2, ok, "successful entry %d", i)
	}
	for _, h := range unresolved {
		_, ok := getCacheEntry(courier, h)
		require.True(t, ok, "unresolved entry must never be evicted")
	}
	_, ok := getCacheEntry(courier, *newHash)
	require.True(t, ok)
	require.Equal(t, 19, dedupCacheLen(courier))
}

func TestDedupCacheCapRefusesWhenAllUnresolved(t *testing.T) {
	courier := newCappedTestCourier(t, 5)
	defer courier.Halt()

	var unresolved [][hash.HashSize]byte
	for i := 0; i < 5; i++ {
		unresolved = append(unresolved, *insertEnvelope(t, courier, fmt.Sprintf("unresolved-%d", i)))
	}

	allowSweep(courier)
	envelope := capTestEnvelope("refused")

	// Hold inFlightLock: a refused envelope must not reach
	// scheduleReplicaDispatch, which would block on it.
	courier.inFlightLock.Lock()
	replyCh := make(chan *pigeonhole.CourierQueryReply, 1)
	go func() { replyCh <- courier.cacheHandleCourierEnvelope(0, envelope) }()
	var reply *pigeonhole.CourierQueryReply
	select {
	case reply = <-replyCh:
		courier.inFlightLock.Unlock()
	case <-time.After(5 * time.Second):
		courier.inFlightLock.Unlock()
		t.Fatal("refused envelope was dispatched")
	}

	require.Equal(t, pigeonhole.EnvelopeErrorCourierBusy, reply.EnvelopeReply.ErrorCode)
	require.True(t, pigeonhole.IsTemporaryEnvelopeError(reply.EnvelopeReply.ErrorCode))
	require.Equal(t, *envelope.EnvelopeHash(), reply.EnvelopeReply.EnvelopeHash)
	_, ok := getCacheEntry(courier, *envelope.EnvelopeHash())
	require.False(t, ok, "a refused envelope must not create an entry")
	for _, h := range unresolved {
		_, ok := getCacheEntry(courier, h)
		require.True(t, ok, "unresolved entry must never be evicted")
	}
	require.Equal(t, 5, dedupCacheLen(courier))

	// Once an unresolved entry expires the client's retry is accepted.
	courier.dedupCacheLock.Lock()
	courier.dedupCache[unresolved[0]].CreatedAt = time.Now().Add(-2 * DedupCacheTTL)
	courier.lastDedupSweep = time.Time{}
	courier.dedupCacheLock.Unlock()
	insertEnvelope(t, courier, "refused")
}

func TestDedupCacheCapSweepIsRateLimited(t *testing.T) {
	courier := newCappedTestCourier(t, 3)
	defer courier.Halt()

	stale := insertEnvelope(t, courier, "stale")
	insertEnvelope(t, courier, "a")
	insertEnvelope(t, courier, "b")
	courier.dedupCacheLock.Lock()
	courier.dedupCache[*stale].CreatedAt = time.Now().Add(-2 * DedupCacheTTL)
	courier.lastDedupSweep = time.Now()
	courier.dedupCacheLock.Unlock()

	// A sweep ran less than dedupSweepInterval ago, so a full cache
	// refuses without scanning, even though an entry has expired.
	reply := courier.cacheHandleCourierEnvelope(0, capTestEnvelope("c"))
	require.Equal(t, pigeonhole.EnvelopeErrorCourierBusy, reply.EnvelopeReply.ErrorCode)
	courier.dedupCacheLock.Lock()
	_, ok := courier.dedupCache[*stale]
	courier.dedupCacheLock.Unlock()
	require.True(t, ok, "no scan may run within dedupSweepInterval")

	allowSweep(courier)
	insertEnvelope(t, courier, "c")
	_, ok = getCacheEntry(courier, *stale)
	require.False(t, ok)
}
