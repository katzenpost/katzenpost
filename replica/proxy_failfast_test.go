// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// FailPeer must fail only the requests targeting the dead peer, and a
// waiter on a failed request must observe a nil reply immediately.
func TestProxyManagerFailPeer(t *testing.T) {
	t.Parallel()

	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	m := NewProxyRequestManager(backendLog.GetLogger("test"), time.Minute)
	defer m.Shutdown()

	peerA := [32]byte{1}
	peerB := [32]byte{2}
	hashA := [32]byte{0xaa}
	hashB := [32]byte{0xbb}

	chA := m.RegisterProxyRequest(hashA, nil, nil, nil, peerA, "storagereplicaA")
	chB := m.RegisterProxyRequest(hashB, nil, nil, nil, peerB, "storagereplicaB")

	m.FailPeer(peerA)

	select {
	case reply, ok := <-chA:
		require.Nil(t, reply)
		require.False(t, ok)
	case <-time.After(time.Second):
		t.Fatal("waiter on failed peer did not observe closure")
	}

	select {
	case <-chB:
		t.Fatal("unrelated peer's request must stay pending")
	default:
	}
}

// FailRequest must fail exactly the named request and leave the rest
// pending, so an undeliverable proxy request fails over to the
// co-holder at once instead of burning its share of the sweep budget
// against a command that was never put on the wire.
func TestProxyManagerFailRequest(t *testing.T) {
	t.Parallel()

	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	m := NewProxyRequestManager(backendLog.GetLogger("test"), time.Minute)
	defer m.Shutdown()

	peer := [32]byte{1}
	hashA := [32]byte{0xaa}
	hashB := [32]byte{0xbb}

	chA := m.RegisterProxyRequest(hashA, nil, nil, nil, peer, "storagereplicaA")
	chB := m.RegisterProxyRequest(hashB, nil, nil, nil, peer, "storagereplicaA")

	m.FailRequest(hashA, "undeliverable")

	select {
	case reply, ok := <-chA:
		require.Nil(t, reply)
		require.False(t, ok)
	case <-time.After(time.Second):
		t.Fatal("waiter on the failed request did not observe closure")
	}

	select {
	case <-chB:
		t.Fatal("another request to the same peer must stay pending")
	default:
	}

	// Failing an unknown hash, or the same one twice, must not panic
	// or close an already-closed channel.
	require.NotPanics(t, func() {
		m.FailRequest(hashA, "undeliverable")
		m.FailRequest([32]byte{0xff}, "undeliverable")
	})
}

// A proxy request that cannot be dispatched must be failed rather than
// parked in the retry queue: the waiter's deadline is already running,
// and a delivery minutes later serves nobody while spending capacity on
// a link that is by definition already struggling.
func TestDispatchCommandFailsProxyRequestInsteadOfQueueing(t *testing.T) {
	co := newTestConnector(t)
	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	proxyManager := NewProxyRequestManager(backendLog.GetLogger("test"), time.Minute)
	defer proxyManager.Shutdown()
	co.server = &Server{proxyManager: proxyManager}

	peer := peerID(0xDD)
	msg := &commands.ReplicaMessage{
		SenderEPubKey: []byte{1, 2, 3, 4},
		DEK:           &[60]byte{},
		Ciphertext:    []byte("proxied read"),
	}
	waiter := proxyManager.RegisterProxyRequest(*msg.EnvelopeHash(), nil, nil, msg, peer, "storagereplicaA")

	// No connection exists for this peer.
	co.DispatchCommand(msg, &peer)

	select {
	case reply, ok := <-waiter:
		require.Nil(t, reply)
		require.False(t, ok, "the waiter must be failed, not left to time out")
	case <-time.After(time.Second):
		t.Fatal("undeliverable proxy request did not fail its waiter")
	}
	require.Empty(t, co.retryQueue, "a proxy request must never enter the retry queue")

	// A replication write in the same situation still queues.
	co.DispatchCommand(writeCmd(7), &peer)
	require.Len(t, co.retryQueue, 1, "replication writes keep the retry queue")
}

// TestProxyResponseChannelIsBufferedAndSingleOwner pins the lifecycle
// that lets FailPeer, FailRequest, HandleReply, CleanupExpiredRequests
// and Shutdown all dispose of a pending request safely.
//
// Two properties hold it together. The response channel has capacity
// one, so the goroutine delivering a reply never blocks on a waiter
// that has already given up and walked away. And the map entry is the
// single ownership token: every disposal path closes the channel only
// while holding the lock and only after finding the entry, then deletes
// it, so no channel can be closed twice however the paths interleave.
func TestProxyResponseChannelIsBufferedAndSingleOwner(t *testing.T) {
	t.Parallel()

	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	m := NewProxyRequestManager(backendLog.GetLogger("test"), time.Minute)
	defer m.Shutdown()

	peer := [32]byte{1}
	hash := [32]byte{0xaa}
	ch := m.RegisterProxyRequest(hash, nil, nil, nil, peer, "storagereplicaA")
	require.Equal(t, 1, cap(ch),
		"the response channel must be buffered so delivering a reply never blocks on an absent waiter")

	// Nobody is reading. HandleReply must still complete rather than
	// park the caller, which on the real path is an outgoing
	// connection's event loop.
	done := make(chan bool, 1)
	go func() {
		done <- m.HandleReply(&commands.ReplicaMessageReply{EnvelopeHash: &hash})
	}()
	select {
	case handled := <-done:
		require.True(t, handled)
	case <-time.After(5 * time.Second):
		t.Fatal("HandleReply blocked on an unread response channel")
	}

	// The entry is gone, so every other disposal path is a no-op rather
	// than a second close.
	require.NotPanics(t, func() {
		m.FailRequest(hash, "undeliverable")
		m.FailPeer(peer)
		m.CleanupExpiredRequests(0)
	})

	reply, ok := <-ch
	require.NotNil(t, reply, "the buffered reply survives for the waiter to collect")
	require.True(t, ok)
	_, ok = <-ch
	require.False(t, ok, "and the channel is closed exactly once")
}

// TestProxyRequestDisposalPathsRace runs the disposal paths against each
// other under the race detector: whichever wins, the rest must find no
// entry and do nothing.
func TestProxyRequestDisposalPathsRace(t *testing.T) {
	t.Parallel()

	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	m := NewProxyRequestManager(backendLog.GetLogger("test"), time.Minute)
	defer m.Shutdown()

	for i := 0; i < 50; i++ {
		peer := [32]byte{byte(i)}
		hash := [32]byte{byte(i), 0xbb}
		ch := m.RegisterProxyRequest(hash, nil, nil, nil, peer, "storagereplicaA")

		var wg sync.WaitGroup
		wg.Add(4)
		go func() { defer wg.Done(); m.FailRequest(hash, "undeliverable") }()
		go func() { defer wg.Done(); m.FailPeer(peer) }()
		go func() { defer wg.Done(); m.HandleReply(&commands.ReplicaMessageReply{EnvelopeHash: &hash}) }()
		go func() { defer wg.Done(); m.CleanupExpiredRequests(0) }()
		wg.Wait()

		// Whoever won, the waiter is released exactly once.
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatal("waiter was never released by any disposal path")
		}
	}
}

// TestHandleReplyReleasesWaiterDuringShutdown covers the case that made
// the obvious version of "do the channel work outside the lock" wrong.
//
// Once HandleReply removes the map entry it is the channel's exclusive
// owner, and Shutdown can no longer reach it. So HandleReply must always
// finish the job, even with the manager's context already cancelled: an
// early return there would leave the waiter to sit out its whole share
// of the sweep budget instead of failing over to the co-holder.
func TestHandleReplyReleasesWaiterDuringShutdown(t *testing.T) {
	t.Parallel()

	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	m := NewProxyRequestManager(backendLog.GetLogger("test"), time.Minute)

	// Cancel the manager's context without disturbing the entries,
	// which is the window Shutdown passes through.
	m.cancel()

	// Repeat, because a version that selects between the send and
	// ctx.Done() has both cases ready here and Go picks uniformly at
	// random among ready cases. One iteration would catch such a bug
	// only half the time; twenty makes it a reliable detector.
	const iterations = 20
	for i := 0; i < iterations; i++ {
		peer := [32]byte{byte(i)}
		hash := [32]byte{byte(i), 0xaa}
		ch := m.RegisterProxyRequest(hash, nil, nil, nil, peer, "storagereplicaA")

		require.True(t, m.HandleReply(&commands.ReplicaMessageReply{EnvelopeHash: &hash}),
			"a reply must still be routed once its request has been claimed (iteration %d)", i)

		select {
		case reply, ok := <-ch:
			require.NotNil(t, reply)
			require.True(t, ok)
		case <-time.After(5 * time.Second):
			t.Fatalf("waiter was orphaned by a reply arriving during shutdown (iteration %d)", i)
		}
		_, ok := <-ch
		require.False(t, ok, "the channel must still be closed exactly once (iteration %d)", i)
	}

	m.Shutdown()
}
