// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/pigeonhole"
)

// buildTestTombstoneMessages returns a ReplicaMessage pair that share
// SenderEPubKey + Ciphertext (the only fields EnvelopeHash() reads), so
// both messages produce the same envHash — exactly matching the shape
// the real tombstone path produces via a single MKEM multi-recipient
// encapsulation.
func buildTestTombstoneMessages(replicaIDs []uint8, tag byte) ([]*commands.ReplicaMessage, *[hash.HashSize]byte) {
	senderKey := bytes.Repeat([]byte{tag}, 16)
	ciphertext := bytes.Repeat([]byte{tag ^ 0xff}, 32)
	msgs := make([]*commands.ReplicaMessage, len(replicaIDs))
	for i := range replicaIDs {
		msgs[i] = &commands.ReplicaMessage{
			SenderEPubKey: senderKey,
			DEK:           &[60]byte{},
			Ciphertext:    ciphertext,
		}
	}
	return msgs, msgs[0].EnvelopeHash()
}

// driveTombstoneAttempts counts SendMessage invocations the fakeConnector
// observes and injects replies via HandleReply once the courier has
// dispatched to every shard in the attempt. Returns when dispatchTombstone
// has terminated.
func driveTombstoneDispatch(
	t *testing.T,
	courier *Courier,
	conn *fakeConnector,
	envHash *[hash.HashSize]byte,
	replicaIDs []uint8,
	messages []*commands.ReplicaMessage,
	replyPlans [][]uint8, // one entry per attempt; entry[i] is the ErrorCode for replicaIDs[i]
) bool {
	t.Helper()

	resultCh := make(chan bool, 1)
	go func() {
		resultCh <- courier.dispatchTombstone(envHash, replicaIDs, messages)
	}()

	for attempt, plan := range replyPlans {
		// Wait for one SendMessage per replica this attempt before injecting replies.
		for range replicaIDs {
			select {
			case <-conn.sendCalledCh:
			case <-time.After(8 * time.Second):
				t.Fatalf("attempt %d: SendMessage not observed in time", attempt+1)
			}
		}
		for i, code := range plan {
			courier.HandleReply(&commands.ReplicaMessageReply{
				EnvelopeHash: envHash,
				ReplicaID:    replicaIDs[i],
				ErrorCode:    code,
			})
		}
	}

	select {
	case ok := <-resultCh:
		return ok
	case <-time.After(30 * time.Second):
		t.Fatal("dispatchTombstone did not return in time")
		return false
	}
}

// TestDispatchTombstoneBothSuccess is the happy path — both shards
// return ReplicaSuccess on the first attempt.
func TestDispatchTombstoneBothSuccess(t *testing.T) {
	courier := createTestCourier(t)
	conn := newFakeConnector()
	courier.server.connector = conn

	replicaIDs := []uint8{3, 4}
	messages, envHash := buildTestTombstoneMessages(replicaIDs, 0xAA)

	ok := driveTombstoneDispatch(t, courier, conn, envHash, replicaIDs, messages, [][]uint8{
		{pigeonhole.ReplicaSuccess, pigeonhole.ReplicaSuccess},
	})
	require.True(t, ok, "both shards returning ReplicaSuccess must yield dispatch success")
}

// TestDispatchTombstoneOneSuccessCountsAsSuccess pins the K=2 redundancy
// invariant: one shard replica confirming is enough, because the peer
// will receive the tombstone via replica-to-replica replication.
func TestDispatchTombstoneOneSuccessCountsAsSuccess(t *testing.T) {
	courier := createTestCourier(t)
	conn := newFakeConnector()
	courier.server.connector = conn

	replicaIDs := []uint8{5, 6}
	messages, envHash := buildTestTombstoneMessages(replicaIDs, 0xBB)

	ok := driveTombstoneDispatch(t, courier, conn, envHash, replicaIDs, messages, [][]uint8{
		{pigeonhole.ReplicaSuccess, pigeonhole.ReplicaErrorDatabaseFailure},
	})
	require.True(t, ok, "one success must count as overall success")
}

// TestDispatchTombstoneRetriesOnAllErrors verifies the retry loop: if
// every shard returns an error on the first attempt, a second attempt
// fires. If that second attempt succeeds, dispatch returns true. This
// is the behavior that makes tombstone cleanup robust to transient
// replica database errors.
func TestDispatchTombstoneRetriesOnAllErrors(t *testing.T) {
	courier := createTestCourier(t)
	conn := newFakeConnector()
	courier.server.connector = conn

	replicaIDs := []uint8{7, 8}
	messages, envHash := buildTestTombstoneMessages(replicaIDs, 0xCC)

	ok := driveTombstoneDispatch(t, courier, conn, envHash, replicaIDs, messages, [][]uint8{
		{pigeonhole.ReplicaErrorDatabaseFailure, pigeonhole.ReplicaErrorDatabaseFailure},
		{pigeonhole.ReplicaSuccess, pigeonhole.ReplicaErrorDatabaseFailure},
	})
	require.True(t, ok, "retry after all-errors must succeed on the second attempt")
}

// TestDispatchTombstoneSingleShardSuccess covers the degraded case
// where only one shard's envelope key was usable (the other shard's
// key was missing or failed to unmarshal). The dispatch still works
// with a single replica and a single reply.
func TestDispatchTombstoneSingleShardSuccess(t *testing.T) {
	courier := createTestCourier(t)
	conn := newFakeConnector()
	courier.server.connector = conn

	replicaIDs := []uint8{9}
	messages, envHash := buildTestTombstoneMessages(replicaIDs, 0xDD)

	ok := driveTombstoneDispatch(t, courier, conn, envHash, replicaIDs, messages, [][]uint8{
		{pigeonhole.ReplicaSuccess},
	})
	require.True(t, ok)
}
