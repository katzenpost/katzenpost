// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// TestDrainToRetryQueueSkipsProxyRequests covers the drain that runs
// between session attempts, when the per-peer FIFO still holds commands
// the dead session never sent.
//
// A replication write belongs in the retry queue: it has no waiter and
// the next session should deliver it. A proxy request does not. By the
// time this runs, FailPeer has already failed every request pending
// against this peer, so re-queuing one delivers minutes later to a
// waiter that gave up long ago, spending capacity on a link that was by
// definition already in trouble.
func TestDrainToRetryQueueSkipsProxyRequests(t *testing.T) {
	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	co := newTestConnector(t)
	c := &outgoingConn{
		log: backendLog.GetLogger("test"),
		dst: &cpki.ReplicaDescriptor{Name: "storagereplica9", IdentityKey: []byte("identity")},
		co:  co,
		ch:  make(chan commands.Command, 8),
	}

	c.ch <- writeCmd(1)
	c.ch <- &commands.ReplicaMessage{
		SenderEPubKey: []byte{1, 2, 3, 4},
		DEK:           &[60]byte{},
		Ciphertext:    []byte("a proxied read nobody is waiting for any more"),
	}
	c.ch <- writeCmd(2)

	c.drainToRetryQueue()

	require.Empty(t, c.ch, "the FIFO must be drained completely")
	require.Len(t, co.retryQueue, 2, "both replication writes are kept, the proxy request is not")
	for _, entry := range co.retryQueue {
		require.IsType(t, &commands.ReplicaWrite{}, entry.cmd,
			"a proxy request must never reach the retry queue")
	}
}
