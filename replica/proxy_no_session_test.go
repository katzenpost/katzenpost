// SPDX-FileCopyrightText: Copyright (C) 2026 Katzenpost Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// noSessionEnv is a connector holding one outgoing connection to a peer
// that has never handshaked, which is what a shard holder whose process
// is down looks like for as long as it stays in the PKI document: the
// connection object exists and its worker keeps redialling, but nothing
// can carry a command.
type noSessionEnv struct {
	co           *Connector
	conn         *outgoingConn
	peer         [32]byte
	proxyManager *ProxyRequestManager
}

func newNoSessionEnv(t *testing.T) *noSessionEnv {
	t.Helper()
	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	proxyManager := NewProxyRequestManager(backendLog.GetLogger("test"), time.Minute)
	t.Cleanup(proxyManager.Shutdown)

	co := newTestConnector(t)
	co.server = &Server{proxyManager: proxyManager}

	peer := peerID(0xAB)
	conn := &outgoingConn{
		log: backendLog.GetLogger("test"),
		dst: &cpki.ReplicaDescriptor{Name: "storagereplica9", IdentityKey: []byte("identity")},
		co:  co,
		ch:  make(chan commands.Command, 8),
	}
	co.conns = map[[32]byte]*outgoingConn{peer: conn}

	require.False(t, conn.sessionUp.Load(), "a connection that never handshaked has no session")
	return &noSessionEnv{co: co, conn: conn, peer: peer, proxyManager: proxyManager}
}

func noSessionProxyRequest(payload string) *commands.ReplicaMessage {
	return &commands.ReplicaMessage{
		SenderEPubKey: []byte{1, 2, 3, 4},
		DEK:           &[60]byte{},
		Ciphertext:    []byte(payload),
	}
}

// TestDispatchToPeerWithNoSessionFailsProxyRequest is the regression
// test for the failover hole that the deterministic integration test
// exposed.
//
// The three fast-fail paths all missed this peer. The connector fails a
// request only when it holds no connection for the destination, and it
// holds one here. dispatchCommand fails it only when the per-peer queue
// is full, and this one has room. FailPeer runs only when an
// established session ends, and a peer that never handshakes never arms
// it. So the request was parked on a queue that nothing would drain,
// and the sweep sat out its whole share of the budget against a peer
// known to be refusing connections before it tried the co-holder.
func TestDispatchToPeerWithNoSessionFailsProxyRequest(t *testing.T) {
	env := newNoSessionEnv(t)

	msg := noSessionProxyRequest("a proxied read for a holder that is down")
	waiter := env.proxyManager.RegisterProxyRequest(*msg.EnvelopeHash(), nil, nil, msg, env.peer, env.conn.dst.Name)

	env.co.DispatchCommand(msg, &env.peer)

	select {
	case reply, ok := <-waiter:
		require.Nil(t, reply)
		require.False(t, ok, "the waiter must be failed so its sweep fails over now")
	case <-time.After(time.Second):
		t.Fatal("a proxy request to a peer with no session was neither delivered nor failed")
	}
	require.Empty(t, env.conn.ch, "the request must not be parked on a queue nothing will drain")
	require.Empty(t, env.co.retryQueue, "a proxy request must never enter the retry queue")
}

// A replication write in the same situation still queues: it has no
// waiter and the per-peer FIFO is exactly where it should wait for the
// peer to come back.
func TestDispatchToPeerWithNoSessionStillQueuesReplication(t *testing.T) {
	env := newNoSessionEnv(t)

	env.co.DispatchCommand(writeCmd(7), &env.peer)

	require.Len(t, env.conn.ch, 1, "a replication write keeps the per-peer queue")
	require.Empty(t, env.co.retryQueue)
}

// Once a session is up the queue is the right place for a proxy request
// again, so the fast-fail must not fire on a healthy peer.
func TestDispatchToPeerWithSessionQueuesProxyRequest(t *testing.T) {
	env := newNoSessionEnv(t)
	env.conn.sessionUp.Store(true)

	msg := noSessionProxyRequest("a proxied read for a holder that is up")
	waiter := env.proxyManager.RegisterProxyRequest(*msg.EnvelopeHash(), nil, nil, msg, env.peer, env.conn.dst.Name)

	env.co.DispatchCommand(msg, &env.peer)

	require.Len(t, env.conn.ch, 1, "a live session must carry the request rather than fail it")
	select {
	case <-waiter:
		t.Fatal("a request handed to a live session must not be failed")
	default:
	}
}
