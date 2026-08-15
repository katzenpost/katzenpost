// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/pigeonhole"
)

// handleCommandTestConn builds an outgoing connection with a real proxy
// request manager behind a mock connector, which is all handleCommand
// touches.
func handleCommandTestConn(t *testing.T) (*outgoingConn, *ProxyRequestManager) {
	t.Helper()

	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	proxyManager := NewProxyRequestManager(backendLog.GetLogger("proxy manager"), time.Minute)
	t.Cleanup(proxyManager.Shutdown)

	server := &Server{proxyManager: proxyManager}
	c := &outgoingConn{
		log: backendLog.GetLogger("test"),
		dst: &cpki.ReplicaDescriptor{Name: "storagereplica9"},
		co:  newMockConnector(server),
	}
	return c, proxyManager
}

// TestHandleCommandRoutesRepliesOutOfOrder is the property that makes it
// safe to stop gating sends on replies.
//
// Once the writer no longer waits for a reply, "the reply to the command
// we just sent" stops existing: the responder jitters each reply through
// its timer queue, so replies overtake one another freely. Attribution
// therefore has to come from the reply itself. This drives two proxy
// requests and answers the second one first, which the old sendAndRecv
// could not have coped with, since it treated whatever arrived as the
// answer to the command in hand.
func TestHandleCommandRoutesRepliesOutOfOrder(t *testing.T) {
	t.Parallel()
	c, proxyManager := handleCommandTestConn(t)

	peer := [32]byte{9}
	firstHash := [32]byte{0x01}
	secondHash := [32]byte{0x02}
	firstWaiter := proxyManager.RegisterProxyRequest(firstHash, nil, nil, nil, peer, "storagereplica9")
	secondWaiter := proxyManager.RegisterProxyRequest(secondHash, nil, nil, nil, peer, "storagereplica9")

	// The second request's reply arrives first.
	require.True(t, c.handleCommand(&commands.ReplicaMessageReply{EnvelopeHash: &secondHash}))

	select {
	case reply, ok := <-secondWaiter:
		require.True(t, ok)
		require.NotNil(t, reply)
		require.Equal(t, secondHash, *reply.EnvelopeHash)
	case <-time.After(5 * time.Second):
		t.Fatal("the reply was not routed to the request it belongs to")
	}

	select {
	case <-firstWaiter:
		t.Fatal("an out-of-order reply must not release an unrelated request")
	default:
	}

	// And the first request's own reply still reaches it afterwards.
	require.True(t, c.handleCommand(&commands.ReplicaMessageReply{EnvelopeHash: &firstHash}))
	reply, ok := <-firstWaiter
	require.True(t, ok)
	require.Equal(t, firstHash, *reply.EnvelopeHash)
}

// TestHandleCommandSurvivesUnattributableReplies checks the session is
// not torn down by replies it can do nothing with. A reply for a request
// that already timed out, and a command type this build predates, must
// both be tolerated: tearing down here would orphan every other reply
// in flight on the connection.
func TestHandleCommandSurvivesUnattributableReplies(t *testing.T) {
	t.Parallel()
	c, _ := handleCommandTestConn(t)

	unknownHash := [32]byte{0xff}
	require.True(t, c.handleCommand(&commands.ReplicaMessageReply{EnvelopeHash: &unknownHash}),
		"a reply for a request that is gone must not kill the session")
	require.True(t, c.handleCommand(&commands.ReplicaMessageReply{}),
		"a reply with no envelope hash must not kill the session")
	require.True(t, c.handleCommand(&commands.ReplicaWrite{}),
		"an unhandled command type must be tolerated")
	require.True(t, c.handleCommand(&commands.ReplicaDecoy{}))
	require.True(t, c.handleCommand(&commands.NoOp{}))
}

// TestHandleCommandDisconnectClosesSession pins the one command that
// does end the session.
func TestHandleCommandDisconnectClosesSession(t *testing.T) {
	t.Parallel()
	c, _ := handleCommandTestConn(t)
	require.False(t, c.handleCommand(&commands.Disconnect{}))
}

// TestHandleReplicaWriteReplyDoesNotRetry documents the consequence of
// the same unordering: ReplicaWriteReply carries an error code and no
// BoxID, so on a link where replies overtake one another it cannot be
// attributed to the write that produced it. A transient error is
// therefore counted, not retried. The previous code retried whichever
// command was in hand, which re-sent an unrelated write and, when that
// command was a decoy, dropped the failed one in silence.
func TestHandleReplicaWriteReplyDoesNotRetry(t *testing.T) {
	t.Parallel()
	c, _ := handleCommandTestConn(t)

	for _, code := range []uint8{
		pigeonhole.ReplicaSuccess,
		pigeonhole.ReplicaErrorBoxAlreadyExists,
		pigeonhole.ReplicaErrorDatabaseFailure, // transient
		pigeonhole.ReplicaErrorInternalError,   // transient
		pigeonhole.ReplicaErrorInvalidSignature,
	} {
		require.True(t, c.handleCommand(&commands.ReplicaWriteReply{ErrorCode: code}),
			"error code %d must not tear the session down", code)
	}
}
