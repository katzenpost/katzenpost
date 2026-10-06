// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func startConsensusReplyDelivery(c *connection, request *getConsensusCtx, reply interface{}) <-chan struct{} {
	delivered := make(chan struct{})
	go func() {
		c.deliverConsensusReply(request, reply)
		close(delivered)
	}()
	return delivered
}

func TestDeliverConsensusReplyWaitsForRoomInsteadOfDropping(t *testing.T) {
	c := newTestConnection(t)
	request := &getConsensusCtx{replyCh: make(chan interface{}, 1)}
	request.replyCh <- ErrNotConnected
	reply := &commands.Consensus2{ErrorCode: commands.ConsensusGone}

	delivered := startConsensusReplyDelivery(c, request, reply)
	select {
	case <-delivered:
		t.Fatal("deliverConsensusReply returned while the reply channel was full")
	case <-time.After(100 * time.Millisecond):
	}

	require.Equal(t, ErrNotConnected, <-request.replyCh)
	select {
	case <-delivered:
	case <-time.After(time.Second):
		t.Fatal("deliverConsensusReply did not deliver once the reply channel had room")
	}
	require.Same(t, reply, <-request.replyCh)
}

func TestDeliverConsensusReplyReturnsOnHalt(t *testing.T) {
	c := newTestConnection(t)
	request := &getConsensusCtx{replyCh: make(chan interface{}, 1)}
	request.replyCh <- ErrNotConnected

	delivered := startConsensusReplyDelivery(c, request, ErrNotConnected)
	c.Halt()
	select {
	case <-delivered:
	case <-time.After(time.Second):
		t.Fatal("deliverConsensusReply did not return after Halt")
	}
}

func TestDeliverConsensusReplyFillsAnEmptyBuffer(t *testing.T) {
	c := newTestConnection(t)
	request := &getConsensusCtx{replyCh: make(chan interface{}, 1)}

	c.deliverConsensusReply(request, ErrNotConnected)
	require.Equal(t, ErrNotConnected, <-request.replyCh)
}
