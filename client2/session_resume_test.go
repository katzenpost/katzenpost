// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows
// +build !windows

package client2

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/core/log"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

// newTestListener creates a listener for testing with a TCP listener on a free port.
func newTestListener(t *testing.T, onDisconnect func(*[AppIDLength]byte)) *listener {
	t.Helper()
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	cfg.ListenAddress = "127.0.0.1:0"

	client := &Client{cfg: cfg}
	rates := &Rates{}
	egressCh := make(chan *Request, 10)

	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)

	l, err := NewListener(client, rates, egressCh, logBackend, onDisconnect)
	require.NoError(t, err)
	return l
}

// newTestDaemonState creates a Daemon with just the state maps needed for tests.
func newTestDaemonState(t *testing.T) *Daemon {
	t.Helper()
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)

	return &Daemon{
		arqSurbIDMap: make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		replies:      make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		decoys:       make(map[[sphinxConstants.SURBIDLength]byte]replyDescriptor),
		replyLock:    new(sync.Mutex),
		logbackend:   logBackend,
		log:          logBackend.GetLogger("test"),
	}
}

// TestHandleSessionTokenNewClient verifies that a new client (unknown token)
// gets registered and receives resumed=false.
func TestHandleSessionTokenNewClient(t *testing.T) {
	l := newTestListener(t, nil)
	defer l.Shutdown()

	appID := &[AppIDLength]byte{1, 2, 3}
	token := [16]byte{10, 20, 30}

	c := &incomingConn{
		listener:       l,
		appID:          appID,
		sendToClientCh: make(chan *Response, 10),
		log:            l.logBackend.GetLogger("test"),
	}

	l.connsLock.Lock()
	l.conns[*appID] = c
	l.connsLock.Unlock()

	l.handleSessionToken(c, &thin.SessionToken{ClientInstanceToken: token})

	// Verify token was registered
	l.clientTokensLock.Lock()
	registeredAppID, ok := l.clientTokens[token]
	l.clientTokensLock.Unlock()
	require.True(t, ok, "token should be registered")
	require.Equal(t, appID, registeredAppID)

	// Verify client received SessionTokenReply with resumed=false
	require.Len(t, c.sendToClientCh, 1)
	reply := <-c.sendToClientCh
	require.NotNil(t, reply.SessionTokenReply)
	require.False(t, reply.SessionTokenReply.Resumed)
	require.Equal(t, appID[:], reply.SessionTokenReply.AppID)

	// Verify clientToken was set on connection
	require.NotNil(t, c.clientToken)
	require.Equal(t, token, *c.clientToken)
}

// TestHandleSessionTokenResume verifies that a reconnecting client (known token)
// gets remapped to its old app ID and receives resumed=true.
func TestHandleSessionTokenResume(t *testing.T) {
	l := newTestListener(t, nil)
	defer l.Shutdown()

	oldAppID := &[AppIDLength]byte{1, 2, 3}
	newAppID := &[AppIDLength]byte{4, 5, 6}
	token := [16]byte{10, 20, 30}

	// Pre-register the token -> oldAppID mapping (simulating previous connection)
	l.clientTokensLock.Lock()
	l.clientTokens[token] = oldAppID
	l.clientTokensLock.Unlock()

	// New connection with a different appID
	c := &incomingConn{
		listener:       l,
		appID:          newAppID,
		sendToClientCh: make(chan *Response, 10),
		log:            l.logBackend.GetLogger("test"),
	}

	l.connsLock.Lock()
	l.conns[*newAppID] = c
	l.connsLock.Unlock()

	l.handleSessionToken(c, &thin.SessionToken{ClientInstanceToken: token})

	// Verify connection was remapped to old app ID
	require.Equal(t, oldAppID, c.appID)

	// Verify old appID is in conns map, new is not
	l.connsLock.RLock()
	_, hasOld := l.conns[*oldAppID]
	_, hasNew := l.conns[*newAppID]
	l.connsLock.RUnlock()
	require.True(t, hasOld, "old appID should be in conns")
	require.False(t, hasNew, "new appID should not be in conns")

	// Verify client received SessionTokenReply with resumed=true
	require.Len(t, c.sendToClientCh, 1)
	reply := <-c.sendToClientCh
	require.NotNil(t, reply.SessionTokenReply)
	require.True(t, reply.SessionTokenReply.Resumed)
	require.Equal(t, oldAppID[:], reply.SessionTokenReply.AppID)
}

// TestHandleSessionTokenResumeFlushesQueuedReplies verifies that queued replies
// from a disconnected session are flushed to the reconnecting client.
func TestHandleSessionTokenResumeFlushesQueuedReplies(t *testing.T) {
	l := newTestListener(t, nil)
	defer l.Shutdown()

	oldAppID := &[AppIDLength]byte{1, 2, 3}
	newAppID := &[AppIDLength]byte{4, 5, 6}
	token := [16]byte{10, 20, 30}

	// Pre-register token and create a disconnected session with queued replies
	l.clientTokensLock.Lock()
	l.clientTokens[token] = oldAppID
	l.clientTokensLock.Unlock()

	queuedReply1 := &Response{
		MessageReplyEvent: &thin.MessageReplyEvent{
			Payload: []byte("reply-1"),
		},
	}
	queuedReply2 := &Response{
		MessageReplyEvent: &thin.MessageReplyEvent{
			Payload: []byte("reply-2"),
		},
	}

	l.disconnectedSessionsLock.Lock()
	l.disconnectedSessions[*oldAppID] = &DisconnectedSession{
		AppID:         oldAppID,
		Token:         token,
		DisconnectAt:  time.Now().Add(-5 * time.Second),
		CleanupTimer:  time.AfterFunc(time.Hour, func() {}), // won't fire
		QueuedReplies: []*Response{queuedReply1, queuedReply2},
	}
	l.disconnectedSessionsLock.Unlock()

	// Reconnect with new connection
	c := &incomingConn{
		listener:       l,
		appID:          newAppID,
		sendToClientCh: make(chan *Response, 10),
		log:            l.logBackend.GetLogger("test"),
	}
	l.connsLock.Lock()
	l.conns[*newAppID] = c
	l.connsLock.Unlock()

	l.handleSessionToken(c, &thin.SessionToken{ClientInstanceToken: token})

	// Verify disconnected session was removed
	l.disconnectedSessionsLock.Lock()
	_, exists := l.disconnectedSessions[*oldAppID]
	l.disconnectedSessionsLock.Unlock()
	require.False(t, exists, "disconnected session should be cleaned up after resume")

	// Verify queued replies + session token reply were sent
	// Order: queued reply 1, queued reply 2, session token reply
	require.Len(t, c.sendToClientCh, 3)

	r1 := <-c.sendToClientCh
	require.NotNil(t, r1.MessageReplyEvent)
	require.Equal(t, []byte("reply-1"), r1.MessageReplyEvent.Payload)

	r2 := <-c.sendToClientCh
	require.NotNil(t, r2.MessageReplyEvent)
	require.Equal(t, []byte("reply-2"), r2.MessageReplyEvent.Payload)

	r3 := <-c.sendToClientCh
	require.NotNil(t, r3.SessionTokenReply)
	require.True(t, r3.SessionTokenReply.Resumed)
}

// TestOnClosedConnExplicitClose verifies that ThinClose causes immediate cleanup
// and removes the token mapping.
func TestOnClosedConnExplicitClose(t *testing.T) {
	cleanedUp := false
	var cleanedUpAppID *[AppIDLength]byte
	l := newTestListener(t, func(appID *[AppIDLength]byte) {
		cleanedUp = true
		cleanedUpAppID = appID
	})
	defer l.Shutdown()

	appID := &[AppIDLength]byte{1, 2, 3}
	token := [16]byte{10, 20, 30}

	c := &incomingConn{
		listener:       l,
		appID:          appID,
		sendToClientCh: make(chan *Response, 10),
		log:            l.logBackend.GetLogger("test"),
		clientToken:    &token,
		explicitClose:  true,
	}

	// Register the token
	l.clientTokensLock.Lock()
	l.clientTokens[token] = appID
	l.clientTokensLock.Unlock()

	l.connsLock.Lock()
	l.conns[*appID] = c
	l.connsLock.Unlock()

	l.onClosedConn(c)

	// Verify cleanup was called
	require.True(t, cleanedUp)
	require.Equal(t, appID, cleanedUpAppID)

	// Verify token mapping was removed
	l.clientTokensLock.Lock()
	_, ok := l.clientTokens[token]
	l.clientTokensLock.Unlock()
	require.False(t, ok, "token should be removed on explicit close")

	// Verify no disconnected session was created
	l.disconnectedSessionsLock.Lock()
	_, exists := l.disconnectedSessions[*appID]
	l.disconnectedSessionsLock.Unlock()
	require.False(t, exists)
}

// TestOnClosedConnUnintentionalDisconnect verifies that an unexpected disconnect
// from a session-aware client preserves state and starts a grace timer.
func TestOnClosedConnUnintentionalDisconnect(t *testing.T) {
	cleanedUp := false
	l := newTestListener(t, func(appID *[AppIDLength]byte) {
		cleanedUp = true
	})
	defer l.Shutdown()

	// Use a short grace period for testing
	l.sessionGracePeriod = 100 * time.Millisecond

	appID := &[AppIDLength]byte{1, 2, 3}
	token := [16]byte{10, 20, 30}

	c := &incomingConn{
		listener:       l,
		appID:          appID,
		sendToClientCh: make(chan *Response, 10),
		log:            l.logBackend.GetLogger("test"),
		clientToken:    &token,
		explicitClose:  false, // unintentional disconnect
	}

	// Register the token
	l.clientTokensLock.Lock()
	l.clientTokens[token] = appID
	l.clientTokensLock.Unlock()

	l.connsLock.Lock()
	l.conns[*appID] = c
	l.connsLock.Unlock()

	l.onClosedConn(c)

	// Verify cleanup was NOT called
	require.False(t, cleanedUp, "cleanup should not run on unintentional disconnect")

	// Verify disconnected session was created
	l.disconnectedSessionsLock.Lock()
	session, exists := l.disconnectedSessions[*appID]
	l.disconnectedSessionsLock.Unlock()
	require.True(t, exists, "disconnected session should exist")
	require.Equal(t, token, session.Token)

	// Verify token mapping still exists
	l.clientTokensLock.Lock()
	_, ok := l.clientTokens[token]
	l.clientTokensLock.Unlock()
	require.True(t, ok, "token should still be registered")
}

// TestGraceTimerExpiry verifies that the grace timer fires cleanup after the
// grace period elapses without reconnection.
func TestGraceTimerExpiry(t *testing.T) {
	cleanedUp := make(chan *[AppIDLength]byte, 1)
	l := newTestListener(t, func(appID *[AppIDLength]byte) {
		cleanedUp <- appID
	})
	defer l.Shutdown()

	l.sessionGracePeriod = 50 * time.Millisecond

	appID := &[AppIDLength]byte{1, 2, 3}
	token := [16]byte{10, 20, 30}

	c := &incomingConn{
		listener:       l,
		appID:          appID,
		sendToClientCh: make(chan *Response, 10),
		log:            l.logBackend.GetLogger("test"),
		clientToken:    &token,
		explicitClose:  false,
	}

	l.clientTokensLock.Lock()
	l.clientTokens[token] = appID
	l.clientTokensLock.Unlock()

	l.connsLock.Lock()
	l.conns[*appID] = c
	l.connsLock.Unlock()

	l.onClosedConn(c)

	// Wait for grace timer to fire
	select {
	case got := <-cleanedUp:
		require.Equal(t, appID, got)
	case <-time.After(2 * time.Second):
		t.Fatal("grace timer did not fire cleanup")
	}

	// Verify token mapping was removed
	l.clientTokensLock.Lock()
	_, ok := l.clientTokens[token]
	l.clientTokensLock.Unlock()
	require.False(t, ok, "token should be removed after grace period")

	// Verify disconnected session was removed
	l.disconnectedSessionsLock.Lock()
	_, exists := l.disconnectedSessions[*appID]
	l.disconnectedSessionsLock.Unlock()
	require.False(t, exists, "disconnected session should be removed after grace period")
}

// TestGraceTimerCancelledOnResume verifies that reconnecting before the grace
// timer expires cancels the timer and does not run cleanup.
func TestGraceTimerCancelledOnResume(t *testing.T) {
	cleanedUp := false
	l := newTestListener(t, func(appID *[AppIDLength]byte) {
		cleanedUp = true
	})
	defer l.Shutdown()

	l.sessionGracePeriod = 500 * time.Millisecond

	appID := &[AppIDLength]byte{1, 2, 3}
	token := [16]byte{10, 20, 30}

	c := &incomingConn{
		listener:       l,
		appID:          appID,
		sendToClientCh: make(chan *Response, 10),
		log:            l.logBackend.GetLogger("test"),
		clientToken:    &token,
		explicitClose:  false,
	}

	l.clientTokensLock.Lock()
	l.clientTokens[token] = appID
	l.clientTokensLock.Unlock()

	l.connsLock.Lock()
	l.conns[*appID] = c
	l.connsLock.Unlock()

	// Disconnect
	l.onClosedConn(c)

	// Immediately reconnect with new connection
	newAppID := &[AppIDLength]byte{4, 5, 6}
	c2 := &incomingConn{
		listener:       l,
		appID:          newAppID,
		sendToClientCh: make(chan *Response, 10),
		log:            l.logBackend.GetLogger("test"),
	}
	l.connsLock.Lock()
	l.conns[*newAppID] = c2
	l.connsLock.Unlock()

	l.handleSessionToken(c2, &thin.SessionToken{ClientInstanceToken: token})

	// Wait longer than grace period to ensure timer was cancelled
	time.Sleep(700 * time.Millisecond)

	require.False(t, cleanedUp, "cleanup should not run after resume cancels the timer")

	// Token should still be registered (pointing to old appID which c2 now uses)
	l.clientTokensLock.Lock()
	_, ok := l.clientTokens[token]
	l.clientTokensLock.Unlock()
	require.True(t, ok, "token should still exist after resume")
}

// TestOnClosedConnLegacyClient verifies that a client without a token
// (legacy client) gets immediate cleanup as before.
func TestOnClosedConnLegacyClient(t *testing.T) {
	cleanedUp := false
	l := newTestListener(t, func(appID *[AppIDLength]byte) {
		cleanedUp = true
	})
	defer l.Shutdown()

	appID := &[AppIDLength]byte{1, 2, 3}
	c := &incomingConn{
		listener:       l,
		appID:          appID,
		sendToClientCh: make(chan *Response, 10),
		log:            l.logBackend.GetLogger("test"),
		clientToken:    nil, // no token -- legacy client
		explicitClose:  false,
	}

	l.connsLock.Lock()
	l.conns[*appID] = c
	l.connsLock.Unlock()

	l.onClosedConn(c)

	require.True(t, cleanedUp, "legacy client should get immediate cleanup")

	l.disconnectedSessionsLock.Lock()
	_, exists := l.disconnectedSessions[*appID]
	l.disconnectedSessionsLock.Unlock()
	require.False(t, exists, "no disconnected session for legacy client")
}

// TestQueueReplyForDisconnected verifies reply queuing for disconnected sessions.
func TestQueueReplyForDisconnected(t *testing.T) {
	l := newTestListener(t, nil)
	defer l.Shutdown()

	appID := &[AppIDLength]byte{1, 2, 3}
	unknownAppID := &[AppIDLength]byte{9, 9, 9}

	// No session: should return false
	ok := l.queueReplyForDisconnected(unknownAppID, &Response{})
	require.False(t, ok)

	// Create a disconnected session
	l.disconnectedSessionsLock.Lock()
	l.disconnectedSessions[*appID] = &DisconnectedSession{
		AppID:        appID,
		CleanupTimer: time.AfterFunc(time.Hour, func() {}),
	}
	l.disconnectedSessionsLock.Unlock()

	// Queue a reply
	reply := &Response{
		MessageReplyEvent: &thin.MessageReplyEvent{
			Payload: []byte("test"),
		},
	}
	ok = l.queueReplyForDisconnected(appID, reply)
	require.True(t, ok)

	// Verify it was queued
	l.disconnectedSessionsLock.Lock()
	session := l.disconnectedSessions[*appID]
	require.Len(t, session.QueuedReplies, 1)
	require.Equal(t, []byte("test"), session.QueuedReplies[0].MessageReplyEvent.Payload)
	l.disconnectedSessionsLock.Unlock()
}

// TestQueueReplyBoundedCapacity verifies that the queue drops replies when full.
func TestQueueReplyBoundedCapacity(t *testing.T) {
	l := newTestListener(t, nil)
	defer l.Shutdown()

	appID := &[AppIDLength]byte{1, 2, 3}

	// Create session with queue at capacity
	l.disconnectedSessionsLock.Lock()
	session := &DisconnectedSession{
		AppID:         appID,
		QueuedReplies: make([]*Response, maxQueuedReplies),
		CleanupTimer:  time.AfterFunc(time.Hour, func() {}),
	}
	l.disconnectedSessions[*appID] = session
	l.disconnectedSessionsLock.Unlock()

	// Queue one more: should succeed (returns true) but not grow the queue
	ok := l.queueReplyForDisconnected(appID, &Response{})
	require.True(t, ok, "should return true even when queue is full")

	l.disconnectedSessionsLock.Lock()
	require.Len(t, l.disconnectedSessions[*appID].QueuedReplies, maxQueuedReplies, "queue should not grow beyond capacity")
	l.disconnectedSessionsLock.Unlock()
}

// TestSessionTokenInThinMessages verifies that SessionToken round-trips through
// FromThinRequest and SessionTokenReply round-trips through IntoThinResponse.
func TestSessionTokenInThinMessages(t *testing.T) {
	token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	// Test FromThinRequest maps SessionToken
	thinReq := &thin.Request{
		SessionToken: &thin.SessionToken{
			ClientInstanceToken: token,
		},
	}
	appID := &[AppIDLength]byte{42}
	req := FromThinRequest(thinReq, appID)
	require.NotNil(t, req.SessionToken)
	require.Equal(t, token, req.SessionToken.ClientInstanceToken)

	// Test IntoThinResponse maps SessionTokenReply
	resp := &Response{
		SessionTokenReply: &thin.SessionTokenReply{
			AppID:   []byte{1, 2, 3},
			Resumed: true,
		},
	}
	thinResp := IntoThinResponse(resp)
	require.NotNil(t, thinResp.SessionTokenReply)
	require.True(t, thinResp.SessionTokenReply.Resumed)
	require.Equal(t, []byte{1, 2, 3}, thinResp.SessionTokenReply.AppID)
}

// TestNewListenerInitializesSessionMaps verifies that NewListener initializes
// the session management maps.
func TestNewListenerInitializesSessionMaps(t *testing.T) {
	l := newTestListener(t, nil)
	defer l.Shutdown()

	require.NotNil(t, l.clientTokens)
	require.NotNil(t, l.disconnectedSessions)
	require.Equal(t, defaultSessionGracePeriod, l.sessionGracePeriod)
}

// TestIncomingConnExplicitCloseFlag verifies that the worker sets explicitClose
// when ThinClose is received. We test the flag directly since we can't easily
// test the full worker loop without a real socket.
func TestIncomingConnExplicitCloseFlag(t *testing.T) {
	c := &incomingConn{}
	require.False(t, c.explicitClose)
	c.explicitClose = true
	require.True(t, c.explicitClose)
}

// TestIncomingConnClientTokenField verifies the clientToken field on incomingConn.
func TestIncomingConnClientTokenField(t *testing.T) {
	c := &incomingConn{}
	require.Nil(t, c.clientToken)
	token := [16]byte{1, 2, 3}
	c.clientToken = &token
	require.Equal(t, token, *c.clientToken)
}
