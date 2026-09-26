// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/log"
)

func newGateTestListener(t *testing.T) *listener {
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	return &listener{
		log:                  logBackend.GetLogger("listener"),
		connsLock:            new(sync.RWMutex),
		logBackend:           logBackend,
		conns:                make(map[[AppIDLength]byte]*incomingConn),
		clientTokens:         make(map[[16]byte]*[AppIDLength]byte),
		disconnectedSessions: make(map[[AppIDLength]byte]*DisconnectedSession),
	}
}

func queuedResponses(c *incomingConn) int {
	c.sendQueueMu.Lock()
	defer c.sendQueueMu.Unlock()
	return len(c.sendQueue)
}

func TestBroadcastsWaitForTheSessionTokenReply(t *testing.T) {
	l := newGateTestListener(t)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	c := newIncomingConn(l, server)
	l.connsLock.Lock()
	l.registerConn(c)
	l.connsLock.Unlock()

	require.NoError(t, c.sendPKIDoc([]byte("initial doc")))
	queued := queuedResponses(c)

	l.broadcastPKIDoc([]byte("broadcast doc"))
	require.Equal(t, queued, queuedResponses(c))

	l.handleSessionToken(c, &thin.SessionToken{ClientInstanceToken: [16]byte{1}})
	require.True(t, c.initialSequenceDone.Load())
	require.Equal(t, queued+1, queuedResponses(c))

	l.broadcastPKIDoc([]byte("broadcast doc"))
	require.Equal(t, queued+2, queuedResponses(c))
}

func TestARequestWithoutASessionTokenOpensTheGate(t *testing.T) {
	l := newGateTestListener(t)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	c := newIncomingConn(l, server)
	l.connsLock.Lock()
	l.registerConn(c)
	l.connsLock.Unlock()
	require.False(t, c.initialSequenceDone.Load())

	go c.worker()
	blob, err := cbor.Marshal(&thin.Request{})
	require.NoError(t, err)
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint32(prefix, uint32(len(blob)))
	_, err = client.Write(append(prefix, blob...))
	require.NoError(t, err)

	require.Eventually(t, c.initialSequenceDone.Load, 2*time.Second, 10*time.Millisecond)
}
