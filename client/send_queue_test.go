// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/log"
)

// newNoDropTestConn builds an incomingConn with just enough state for
// sendResponse: the per-conn slice queue, wake channel, and doneCh. No
// writer goroutine is started, so every sendResponse call should land
// in sendQueue and nothing should be dropped.
func newNoDropTestConn(t *testing.T) *incomingConn {
	t.Helper()
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	appID := &[AppIDLength]byte{}
	appID[0] = 0xAA
	return &incomingConn{
		log:      logBackend.GetLogger("no-drop-test"),
		appID:    appID,
		sendWake: make(chan struct{}, 1),
		doneCh:   make(chan struct{}),
	}
}

// TestSendResponse_NeverDropsUnderBurst pins the invariant: sendResponse
// accepts an arbitrarily large burst without dropping. 10_000 responses
// go in, 10_000 come out of sendQueue, in order.
func TestSendResponse_NeverDropsUnderBurst(t *testing.T) {
	c := newNoDropTestConn(t)

	const n = 10000
	for i := 0; i < n; i++ {
		resp := &Response{
			MessageReplyEvent: &thin.MessageReplyEvent{
				Payload: []byte{byte(i), byte(i >> 8)},
			},
		}
		require.NoError(t, c.sendResponse(resp),
			"sendResponse must not fail on a live conn (iteration %d)", i)
	}

	drained := c.drainSendQueue()
	require.Len(t, drained, n, "every enqueued response must survive in sendQueue")

	// Spot-check order preservation.
	for i, resp := range drained {
		require.NotNil(t, resp.MessageReplyEvent)
		require.Equal(t, []byte{byte(i), byte(i >> 8)}, resp.MessageReplyEvent.Payload,
			"FIFO order must be preserved")
	}
}

// TestSendResponse_ReturnsErrorAfterClose verifies that once the conn
// has begun teardown (doneCh closed), sendResponse fails with
// errConnClosed instead of silently queueing onto a dead conn.
func TestSendResponse_ReturnsErrorAfterClose(t *testing.T) {
	c := newNoDropTestConn(t)

	c.closeDone()

	err := c.sendResponse(&Response{
		MessageReplyEvent: &thin.MessageReplyEvent{Payload: []byte("ignored")},
	})
	require.ErrorIs(t, err, errConnClosed,
		"sendResponse must return errConnClosed so callers know delivery failed")

	require.Empty(t, c.drainSendQueue(),
		"no response should have been appended after close")
}

// TestSendResponse_SignalsWake verifies that sendResponse signals the
// wake channel so a waiting writer goroutine notices new work. The wake
// channel has capacity 1 and subsequent signals are coalesced — that is
// deliberate and harmless because the writer drains the full queue on
// each iteration.
func TestSendResponse_SignalsWake(t *testing.T) {
	c := newNoDropTestConn(t)

	require.NoError(t, c.sendResponse(&Response{
		MessageReplyEvent: &thin.MessageReplyEvent{Payload: []byte("a")},
	}))

	select {
	case <-c.sendWake:
	default:
		t.Fatal("sendResponse must signal sendWake so the writer goroutine wakes up")
	}

	// Second sendResponse without draining: the wake signal is coalesced
	// (capacity 1) — this is by design, since the writer drains the full
	// queue on each iteration and does not miss any enqueued response.
	require.NoError(t, c.sendResponse(&Response{
		MessageReplyEvent: &thin.MessageReplyEvent{Payload: []byte("b")},
	}))
	// Exactly one wake is buffered; the second is coalesced away.
	select {
	case <-c.sendWake:
	default:
		t.Fatal("after drain-and-re-enqueue, sendWake should be signalable again")
	}
}
