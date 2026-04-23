// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

// newTestIncomingConn builds an incomingConn with just the fields the
// scheduler touches (appID, requestCh, resendCh). No socket, no worker
// goroutine — tests register these directly on a listener.
func newTestIncomingConn(appIDByte byte, reqBuf, resendBuf int) *incomingConn {
	var appID [AppIDLength]byte
	appID[0] = appIDByte
	c := &incomingConn{
		appID:     &appID,
		requestCh: make(chan *Request, reqBuf),
		resendCh:  make(chan *[sphinxConstants.SURBIDLength]byte, resendBuf),
	}
	return c
}

// newSchedulerListener builds a listener with just the fields the scheduler
// touches, no log backend, no network listener.
func newSchedulerListener() *listener {
	return &listener{
		connsLock: new(sync.RWMutex),
		conns:     make(map[[AppIDLength]byte]*incomingConn),
	}
}

// register adds an incomingConn to the listener's conns map and connOrder
// slice so the scheduler sees it.
func (l *listener) testRegister(c *incomingConn) {
	l.connsLock.Lock()
	l.conns[*c.appID] = c
	l.connOrder = append(l.connOrder, *c.appID)
	l.connsLock.Unlock()
}

func TestPickNext_RoundRobinTwoClients(t *testing.T) {
	l := newSchedulerListener()
	a := newTestIncomingConn(0x0A, 200, 8)
	b := newTestIncomingConn(0x0B, 200, 8)
	l.testRegister(a)
	l.testRegister(b)

	for i := 0; i < 100; i++ {
		a.requestCh <- &Request{AppID: a.appID}
	}
	b.requestCh <- &Request{AppID: b.appID}

	var got []byte
	for i := 0; i < 4; i++ {
		req := l.PickNextRequest()
		require.NotNilf(t, req, "pick %d returned nil", i)
		got = append(got, req.AppID[0])
	}

	// After A is served, cursor advances to B. B has one request and is
	// served on the next pick (not after all 100 of A's). Then we wrap back
	// to A for the remaining picks.
	require.Equal(t, []byte{0x0A, 0x0B, 0x0A, 0x0A}, got)
}

func TestPickNext_AllEmptyReturnsNil(t *testing.T) {
	l := newSchedulerListener()

	// No clients registered: nothing to pick.
	require.Nil(t, l.PickNextRequest())

	// Clients registered but queues empty: still nil (sender will send a decoy).
	a := newTestIncomingConn(0x0A, 8, 8)
	b := newTestIncomingConn(0x0B, 8, 8)
	l.testRegister(a)
	l.testRegister(b)
	require.Nil(t, l.PickNextRequest())
	require.Nil(t, l.PickNextRequest())
}

func TestPickNext_ResendBeatsRequestForSameClient(t *testing.T) {
	l := newSchedulerListener()
	a := newTestIncomingConn(0x0A, 8, 8)
	l.testRegister(a)

	var surbID [sphinxConstants.SURBIDLength]byte
	surbID[0] = 0xCC
	a.resendCh <- &surbID
	a.requestCh <- &Request{AppID: a.appID}

	// Within a client, a pending ARQ resend is picked before a fresh
	// request: retransmits target already-promised work and should not be
	// delayed behind new user input.
	first := l.PickNextRequest()
	require.NotNil(t, first)
	require.NotNil(t, first.ResendARQ, "first pick should be a resend")
	require.Equal(t, byte(0xCC), first.ResendARQ[0])

	// The fresh request is picked on the next tick for this client.
	second := l.PickNextRequest()
	require.NotNil(t, second)
	require.Nil(t, second.ResendARQ)
	require.Equal(t, byte(0x0A), second.AppID[0])
}

func TestPickNext_CursorAdvancesOnEmptyClient(t *testing.T) {
	l := newSchedulerListener()
	a := newTestIncomingConn(0x0A, 8, 8) // empty
	b := newTestIncomingConn(0x0B, 8, 8)
	c := newTestIncomingConn(0x0C, 8, 8)
	l.testRegister(a)
	l.testRegister(b)
	l.testRegister(c)

	b.requestCh <- &Request{AppID: b.appID}
	c.requestCh <- &Request{AppID: c.appID}

	// With A empty, the scheduler must skip past A and serve B. On the next
	// call it should serve C (not re-visit B, which is now empty).
	first := l.PickNextRequest()
	require.NotNil(t, first)
	require.Equal(t, byte(0x0B), first.AppID[0])

	second := l.PickNextRequest()
	require.NotNil(t, second)
	require.Equal(t, byte(0x0C), second.AppID[0])

	// All queues empty now.
	require.Nil(t, l.PickNextRequest())
}

func TestPickNext_DisconnectAdjustsCursor(t *testing.T) {
	l := newSchedulerListener()
	a := newTestIncomingConn(0x0A, 8, 8)
	b := newTestIncomingConn(0x0B, 8, 8)
	c := newTestIncomingConn(0x0C, 8, 8)
	l.testRegister(a)
	l.testRegister(b)
	l.testRegister(c)

	a.requestCh <- &Request{AppID: a.appID}
	b.requestCh <- &Request{AppID: b.appID}
	c.requestCh <- &Request{AppID: c.appID}
	c.requestCh <- &Request{AppID: c.appID}

	// Pick A; cursor now points at B.
	require.Equal(t, byte(0x0A), l.PickNextRequest().AppID[0])

	// Disconnect B. Cursor should continue to a live client (C).
	l.unregisterConn(*b.appID)
	close(b.requestCh)
	close(b.resendCh)

	require.Equal(t, byte(0x0C), l.PickNextRequest().AppID[0])
	// A is empty; scan falls through to C's remaining request.
	require.Equal(t, byte(0x0C), l.PickNextRequest().AppID[0])
	require.Nil(t, l.PickNextRequest())
}

// newSchedulerDaemon builds a Daemon with just the fields enqueueResend
// touches: replyLock, arqSurbIDMap, a listener, and a log.
func newSchedulerDaemon(t *testing.T, l *listener) *Daemon {
	t.Helper()
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	d := &Daemon{
		logbackend:   logBackend,
		log:          logBackend.GetLogger("test"),
		listener:     l,
		replyLock:    new(sync.Mutex),
		arqSurbIDMap: make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
	}
	return d
}

func TestEnqueueResend_RoutesToClientByAppID(t *testing.T) {
	l := newSchedulerListener()
	a := newTestIncomingConn(0x0A, 8, 8)
	b := newTestIncomingConn(0x0B, 8, 8)
	l.testRegister(a)
	l.testRegister(b)

	d := newSchedulerDaemon(t, l)

	var surbID [sphinxConstants.SURBIDLength]byte
	surbID[0] = 0x77
	d.replyLock.Lock()
	d.arqSurbIDMap[surbID] = &ARQMessage{AppID: a.appID, SURBID: &surbID}
	d.replyLock.Unlock()

	d.enqueueResend(&surbID)

	// SURB ID lands on A's resendCh and nowhere else.
	select {
	case got := <-a.resendCh:
		require.Equal(t, &surbID, got)
	default:
		t.Fatal("expected SURB ID on A.resendCh")
	}
	require.Len(t, b.resendCh, 0, "B.resendCh must be empty")
}

func TestEnqueueResend_ReschedulesWhenClientQueueFull(t *testing.T) {
	l := newSchedulerListener()
	const resendBuf = 2
	a := newTestIncomingConn(0x0A, 8, resendBuf)
	l.testRegister(a)

	d := newSchedulerDaemon(t, l)
	// Real arqTimerQueue with a no-op action: we inspect Len() without
	// running any callback.
	d.arqTimerQueue = NewTimerQueue(func(interface{}) {})

	// Fill A's resendCh.
	var filler1, filler2 [sphinxConstants.SURBIDLength]byte
	filler1[0] = 0xF1
	filler2[0] = 0xF2
	a.resendCh <- &filler1
	a.resendCh <- &filler2

	var surbID [sphinxConstants.SURBIDLength]byte
	surbID[0] = 0x77
	d.replyLock.Lock()
	d.arqSurbIDMap[surbID] = &ARQMessage{AppID: a.appID, SURBID: &surbID}
	d.replyLock.Unlock()

	// Must not block. With the per-client queue full, enqueueResend must
	// re-arm the retry on arqTimerQueue — dropping silently would lose
	// this resend forever (arqDoResend is what re-Pushes the timer on
	// success, and it never runs if we drop here).
	d.enqueueResend(&surbID)

	require.Len(t, a.resendCh, resendBuf, "resendCh should still be full")
	// The TimerQueue worker is not running in this test, so the push
	// remains in pushCh (where Push enqueues synchronously) rather than
	// in the internal heap that Len() exposes.
	require.Len(t, d.arqTimerQueue.pushCh, 1, "retry must be re-armed on arqTimerQueue")
	d.replyLock.Lock()
	_, ok := d.arqSurbIDMap[surbID]
	d.replyLock.Unlock()
	require.True(t, ok, "arqSurbIDMap entry must survive across reschedule")
}

func TestEnqueueResend_ClientDisconnectedIsNoOp(t *testing.T) {
	l := newSchedulerListener()
	// No clients registered: the appID maps to nothing.

	d := newSchedulerDaemon(t, l)

	var missingAppID [AppIDLength]byte
	missingAppID[0] = 0xDD
	var surbID [sphinxConstants.SURBIDLength]byte
	surbID[0] = 0x77
	d.replyLock.Lock()
	d.arqSurbIDMap[surbID] = &ARQMessage{AppID: &missingAppID, SURBID: &surbID}
	d.replyLock.Unlock()

	// Must not panic, not block. Stale arqSurbIDMap entry is left for
	// cleanupForAppID to eventually remove.
	require.NotPanics(t, func() { d.enqueueResend(&surbID) })
}

func TestEnqueueResend_UnknownSurbIDIsNoOp(t *testing.T) {
	l := newSchedulerListener()
	a := newTestIncomingConn(0x0A, 8, 8)
	l.testRegister(a)
	d := newSchedulerDaemon(t, l)

	// arqSurbIDMap has no entry for this SURB ID (e.g. already ACKed).
	var surbID [sphinxConstants.SURBIDLength]byte
	surbID[0] = 0x99

	require.NotPanics(t, func() { d.enqueueResend(&surbID) })
	require.Len(t, a.resendCh, 0)
}

func TestSender_PickAndSend_EmitsPickedRequest(t *testing.T) {
	out := make(chan *Request, 1)
	want := &Request{}
	calls := 0
	s := &sender{
		out: out,
		pickNext: func() *Request {
			calls++
			return want
		},
	}

	s.pickAndSend()

	require.Equal(t, 1, calls)
	got := <-out
	require.Same(t, want, got)
}

func TestSender_PickAndSend_EmitsDecoyWhenPickReturnsNil(t *testing.T) {
	out := make(chan *Request, 1)
	s := &sender{
		out:      out,
		pickNext: func() *Request { return nil },
	}

	s.pickAndSend()

	got := <-out
	require.NotNil(t, got.SendLoopDecoy, "nil pick should produce a loop decoy")
}

func TestSender_PickAndSend_DropsTickWhenDecoysDisabled(t *testing.T) {
	out := make(chan *Request, 1)
	s := &sender{
		out:           out,
		pickNext:      func() *Request { return nil },
		disableDecoys: true,
	}

	s.pickAndSend()

	require.Len(t, out, 0, "with decoys disabled and no real work, the tick should be dropped")
}

// TestDispatch_ResendARQInvokesArqDoResend verifies that the egress
// dispatch routes a Request carrying a ResendARQ field into arqDoResend.
// We observe the routing via arqDoResend's "listener nil" cleanup branch:
// it deletes the arqSurbIDMap entry, which is a side effect we can assert
// without running the full Sphinx compose/send path.
func TestDispatch_ResendARQInvokesArqDoResend(t *testing.T) {
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	d := &Daemon{
		logbackend:         logBackend,
		log:                logBackend.GetLogger("test"),
		replyLock:          new(sync.Mutex),
		arqSurbIDMap:       make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		arqEnvelopeHashMap: make(map[[32]byte]*[sphinxConstants.SURBIDLength]byte),
		// Leave listener nil so arqDoResend takes its cleanup branch
		// rather than trying to compose a real Sphinx packet.
	}

	var surbID [sphinxConstants.SURBIDLength]byte
	surbID[0] = 0x55
	appID := &[AppIDLength]byte{}
	appID[0] = 0x0A
	d.replyLock.Lock()
	d.arqSurbIDMap[surbID] = &ARQMessage{AppID: appID, SURBID: &surbID}
	d.replyLock.Unlock()

	d.dispatch(&Request{AppID: appID, ResendARQ: &surbID})

	d.replyLock.Lock()
	_, stillPresent := d.arqSurbIDMap[surbID]
	d.replyLock.Unlock()
	require.False(t, stillPresent,
		"dispatch(ResendARQ) must reach arqDoResend; its listener-nil cleanup should remove the entry")
}
