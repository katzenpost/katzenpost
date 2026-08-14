// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
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

	m.FailRequest(hashA)

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
		m.FailRequest(hashA)
		m.FailRequest([32]byte{0xff})
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
