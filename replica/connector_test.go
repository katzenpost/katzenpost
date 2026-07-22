// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// newTestConnector builds a bare Connector with just the fields the retry-queue
// methods touch. No PKI, no network, no RocksDB.
func newTestConnector(t *testing.T) *Connector {
	t.Helper()
	lb, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	return &Connector{
		log: lb.GetLogger("test-connector"),
	}
}

func writeCmd(boxIDByte byte) *commands.ReplicaWrite {
	var boxID [32]byte
	for i := range boxID {
		boxID[i] = boxIDByte
	}
	return &commands.ReplicaWrite{
		BoxID:     &boxID,
		Signature: &[64]byte{},
		Payload:   []byte{},
	}
}

func peerID(b byte) [32]byte {
	var id [32]byte
	for i := range id {
		id[i] = b
	}
	return id
}

// Regression for the dedup bug: two distinct writes to the same peer must land
// as two entries, not collapse into one.
func TestQueueForRetryAppendsDistinctBoxIDs(t *testing.T) {
	co := newTestConnector(t)
	peer := peerID(0xAA)

	co.QueueForRetry(writeCmd(1), peer)
	co.QueueForRetry(writeCmd(2), peer)
	co.QueueForRetry(writeCmd(3), peer)

	require.Len(t, co.retryQueue, 3)
	require.Equal(t, byte(1), co.retryQueue[0].ident[0])
	require.Equal(t, byte(2), co.retryQueue[1].ident[0])
	require.Equal(t, byte(3), co.retryQueue[2].ident[0])
}

func TestQueueForRetryDedupsExactMatch(t *testing.T) {
	co := newTestConnector(t)
	peer := peerID(0xAA)

	co.QueueForRetry(writeCmd(1), peer)
	co.QueueForRetry(writeCmd(1), peer)
	co.QueueForRetry(writeCmd(1), peer)

	require.Len(t, co.retryQueue, 1)
	require.Equal(t, 3, co.retryQueue[0].attempts)
}

func TestQueueForRetryPerPeerCapacity(t *testing.T) {
	orig := maxRetryQueuePerPeer
	maxRetryQueuePerPeer = 3
	defer func() { maxRetryQueuePerPeer = orig }()

	co := newTestConnector(t)
	peerA := peerID(0xAA)
	peerB := peerID(0xBB)

	// Fill peer A to its cap.
	for i := byte(1); i <= 3; i++ {
		co.QueueForRetry(writeCmd(i), peerA)
	}
	// Queue a distinct entry for peer B — must not be evicted by peer A overflow.
	co.QueueForRetry(writeCmd(100), peerB)

	// Exceed peer A's cap by one.
	co.QueueForRetry(writeCmd(4), peerA)

	// Peer A should still have 3 entries (oldest A was evicted, newest appended).
	// Peer B's entry should be intact.
	aCount, bCount := 0, 0
	var aBoxIDs []byte
	var bBoxIDs []byte
	for _, rc := range co.retryQueue {
		switch rc.idHash {
		case peerA:
			aCount++
			aBoxIDs = append(aBoxIDs, rc.ident[0])
		case peerB:
			bCount++
			bBoxIDs = append(bBoxIDs, rc.ident[0])
		}
	}
	require.Equal(t, 3, aCount, "peer A should be at cap")
	require.Equal(t, 1, bCount, "peer B's entry must not be evicted")
	require.NotContains(t, aBoxIDs, byte(1), "oldest peer-A entry should have been evicted")
	require.Contains(t, aBoxIDs, byte(4), "newest peer-A entry should be present")
	require.Equal(t, []byte{100}, bBoxIDs)
}

// Regression test: the outgoing_conn drain path (outgoing_conn.go:121) feeds
// whatever's in c.ch into QueueForRetry, including *commands.ReplicaMessage from
// proxy requests. The old code panicked via getBoxID on non-ReplicaWrite types.
func TestQueueForRetryAcceptsReplicaMessage(t *testing.T) {
	co := newTestConnector(t)
	peer := peerID(0xCC)

	msg := &commands.ReplicaMessage{
		SenderEPubKey: []byte{1, 2, 3, 4},
		DEK:           &[60]byte{},
		Ciphertext:    []byte("some ciphertext"),
	}
	require.NotPanics(t, func() {
		co.QueueForRetry(msg, peer)
	})
	require.Len(t, co.retryQueue, 1)
	require.True(t, co.retryQueue[0].hasIdent)

	// A second identical message collapses (same EnvelopeHash).
	co.QueueForRetry(msg, peer)
	require.Len(t, co.retryQueue, 1)
	require.Equal(t, 2, co.retryQueue[0].attempts)

	// A message with different ciphertext is a distinct entry.
	msg2 := &commands.ReplicaMessage{
		SenderEPubKey: []byte{1, 2, 3, 4},
		DEK:           &[60]byte{},
		Ciphertext:    []byte("different ciphertext"),
	}
	co.QueueForRetry(msg2, peer)
	require.Len(t, co.retryQueue, 2)
}

func TestPruneRetryQueueDropsExpired(t *testing.T) {
	orig := retryTTL
	retryTTL = 50 * time.Millisecond
	defer func() { retryTTL = orig }()

	co := newTestConnector(t)
	peer := peerID(0xAA)

	co.QueueForRetry(writeCmd(1), peer)
	co.QueueForRetry(writeCmd(2), peer)
	require.Len(t, co.retryQueue, 2)

	time.Sleep(75 * time.Millisecond)

	co.QueueForRetry(writeCmd(3), peer)

	// All expired entries pruned on the next QueueForRetry; only new entry remains.
	require.Len(t, co.retryQueue, 1)
	require.Equal(t, byte(3), co.retryQueue[0].ident[0])
}

// TestProcessRetryQueueFullChannelNoDeadlock is the regression guard for the
// connector self-deadlock that took the namenlos replicas out of consensus.
// processRetryQueue must not dispatch while holding retryQueueMu: when the
// peer's per-peer channel is full, dispatchCommand falls through to
// QueueForRetry, which re-locks retryQueueMu in the same goroutine. Holding
// the lock across the dispatch wedged the connector's retry path forever, and
// through the synchronous pki_change Rebalance it wedged the PKI worker, so the
// replica stopped publishing its descriptor and aged out of the consensus.
// On the buggy code this test times out; with the fix it returns promptly.
func TestProcessRetryQueueFullChannelNoDeadlock(t *testing.T) {
	co := newTestConnector(t)
	co.conns = make(map[[constants.NodeIDLength]byte]*outgoingConn)

	identityKey := []byte("peer-identity-key")
	idHash := hash.Sum256(identityKey)

	// A connected peer whose per-peer channel is already full, so any dispatch
	// to it falls through to QueueForRetry.
	c := &outgoingConn{
		co:  co,
		log: co.log,
		dst: &cpki.ReplicaDescriptor{Name: "peer", IdentityKey: identityKey},
		ch:  make(chan commands.Command, 1),
	}
	c.ch <- writeCmd(0xEE)
	co.conns[idHash] = c

	co.QueueForRetry(writeCmd(0x11), idHash)

	done := make(chan struct{})
	go func() {
		co.processRetryQueue()
		close(done)
	}()

	select {
	case <-done:
		// Returned without deadlocking.
	case <-time.After(5 * time.Second):
		t.Fatal("processRetryQueue deadlocked: it dispatched to a full peer channel while holding retryQueueMu")
	}

	// The channel was full, so the command must have been re-queued, not lost.
	require.Len(t, co.retryQueue, 1)
}
