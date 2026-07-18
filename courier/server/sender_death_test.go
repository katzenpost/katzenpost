// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// noopSession is a wire.SessionInterface that never sends, receives, or
// closes anything real. It stands in for a live session in event-loop
// unit tests that only drive the loop's channel plumbing.
type noopSession struct{}

func (noopSession) Initialize(context.Context, net.Conn) error         { return nil }
func (noopSession) SendCommand(context.Context, commands.Command) error { return nil }
func (noopSession) RecvCommand(context.Context) (commands.Command, error) {
	return nil, nil
}
func (noopSession) Close()                                        {}
func (noopSession) PeerCredentials() (*wire.PeerCredentials, error) { return nil, nil }
func (noopSession) ClockSkew() time.Duration                      { return 0 }

// The command-sender goroutine dying (wire write deadline during a
// partition) while the event loop holds a paced command must not wedge
// the handoff on the unbuffered cmdCh: closeCh only fires on
// connector-wide shutdown, so without the cmdCloseCh escape the session
// would never tear down and the replica would be orphaned until a
// courier restart.
func TestHandleOutgoingCommandSenderDeath(t *testing.T) {
	t.Parallel()

	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	senderIn := make(chan *courierSenderRequest, 1)
	c := &outgoingConn{
		log:    backendLog.GetLogger("test"),
		dst:    &cpki.ReplicaDescriptor{Name: "storagereplica9"},
		sender: &sender{in: senderIn},
	}

	cmdCh := make(chan commands.Command) // unbuffered, no reader: sender is dead
	closeCh := make(chan struct{})       // never fires outside process shutdown
	cmdCloseCh := make(chan error)
	close(cmdCloseCh)

	msg := &commands.ReplicaMessage{}
	type result struct{ done, halted bool }
	resCh := make(chan result, 1)
	go func() {
		done, halted := c.handleOutgoingCommand(msg, cmdCh, closeCh, cmdCloseCh)
		resCh <- result{done, halted}
	}()

	select {
	case res := <-resCh:
		require.True(t, res.done, "session must be torn down")
		require.False(t, res.halted, "must redial, not exit the worker")
	case <-time.After(5 * time.Second):
		t.Fatal("handleOutgoingCommand wedged on dead sender: deadlock regression")
	}

	select {
	case req := <-senderIn:
		require.Same(t, msg, req.ReplicaMessage, "in-hand message must be requeued")
	default:
		t.Fatal("in-hand ReplicaMessage was dropped, not requeued")
	}
}

// Full-loop version: the event loop has already pulled the next paced
// command and is blocked handing it to the sender when the sender dies.
// On the pre-fix code this deterministically deadlocks (test timeout).
func TestRunEventLoopSenderDeathUnblocks(t *testing.T) {
	t.Parallel()

	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	senderIn := make(chan *courierSenderRequest, 4)
	senderOut := make(chan *courierSenderRequest, 1)
	c := &outgoingConn{
		log:    backendLog.GetLogger("test"),
		dst:    &cpki.ReplicaDescriptor{Name: "storagereplica9"},
		sender: &sender{in: senderIn, out: senderOut},
	}

	closeCh := make(chan struct{})
	cmdCh := make(chan commands.Command) // no reader: command sender is dead
	cmdCloseCh := make(chan error)
	receiveCmdCh := make(chan interface{}, 1)
	reauth := time.NewTicker(time.Hour) // never fires; the noop session is never touched
	defer reauth.Stop()

	msg := &commands.ReplicaMessage{}
	senderOut <- &courierSenderRequest{ReplicaMessage: msg}

	resCh := make(chan bool, 1)
	go func() {
		resCh <- c.runEventLoop(noopSession{}, closeCh, reauth, cmdCh, cmdCloseCh, receiveCmdCh)
	}()

	// Wait until the loop has dequeued the paced request and is therefore
	// committed to the cmdCh handoff, then kill the sender.
	require.Eventually(t, func() bool { return len(senderOut) == 0 },
		time.Second, time.Millisecond)
	close(cmdCloseCh)

	select {
	case wasHalted := <-resCh:
		require.False(t, wasHalted, "session death must map to redial (false)")
	case <-time.After(5 * time.Second):
		t.Fatal("runEventLoop wedged after sender death: deadlock regression")
	}

	select {
	case req := <-senderIn:
		require.Same(t, msg, req.ReplicaMessage, "in-hand message must be requeued")
	default:
		t.Fatal("in-hand ReplicaMessage lost on session teardown")
	}
}
