// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/queue"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

// resendCh belongs to one connection, created in newIncomingConn and drained by
// that connection's slot in the scheduler. A SURB ID that is sitting in it when
// the connection goes away is therefore gone with the connection, and
// enqueueResend re-arms the ARQ timer only when it could not hand the SURB ID
// over, so nothing is left to retry. pigeonhole.md has a client resend until it
// receives a reply, so the operation must come back on the timer instead.
func TestClosedConnReArmsItsQueuedResends(t *testing.T) {
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)

	var rearmed atomic.Int32
	d := &Daemon{
		logbackend:         logBackend,
		log:                logBackend.GetLogger("test"),
		replyLock:          new(sync.Mutex),
		arqSurbIDMap:       make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		arqEnvelopeHashMap: make(map[[32]byte]*[sphinxConstants.SURBIDLength]byte),
	}
	d.arqTimerQueue = queue.NewTimerQueue(func(interface{}) { rearmed.Add(1) })
	t.Cleanup(func() { d.arqTimerQueue.Halt() })

	l := newSchedulerListener()
	l.log = logBackend.GetLogger("listener")
	l.sessionGracePeriod = 0
	d.listener = l
	l.SetResendOrphanHandler(d.rearmOrphanedResend)

	conn := newTestIncomingConn(0x0D, 1, 2)
	l.testRegister(conn)

	// One operation tracked, its resend already handed to this connection.
	surbID := &[sphinxConstants.SURBIDLength]byte{}
	copy(surbID[:], []byte("orphan-surb-0001"))
	envHash := &[32]byte{}
	envHash[0] = 0x0D
	m := &ARQMessage{AppID: conn.appID, SURBID: surbID, EnvelopeHash: envHash}
	d.replyLock.Lock()
	d.arqSurbIDMap[*surbID] = m
	d.arqEnvelopeHashMap[*envHash] = surbID
	d.replyLock.Unlock()
	conn.resendCh <- surbID
	require.Len(t, conn.resendCh, 1, "the resend is queued on this connection")

	l.onClosedConn(conn)

	require.Equal(t, 1, d.arqTimerQueue.PushChLen()+int(rearmed.Load()),
		"a resend queued on a connection that goes away must come back on the timer")
}

// Handling a reply for a client that is away inside its grace period means the
// handlers now run with no connection, so any path that still reached for one
// would panic. The copy-command handler had three such sends. This drives the
// terminal delivery with a nil connection and no disconnected session, which is
// the worst case: it must report the loss, not crash the daemon.
func TestDeliverARQResponseSurvivesNoConnection(t *testing.T) {
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)

	d := &Daemon{
		logbackend:         logBackend,
		log:                logBackend.GetLogger("test"),
		listener:           newSchedulerListener(),
		replyLock:          new(sync.Mutex),
		arqSurbIDMap:       make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		arqEnvelopeHashMap: make(map[[32]byte]*[sphinxConstants.SURBIDLength]byte),
	}
	d.listener.log = logBackend.GetLogger("listener")
	d.listener.disconnectedSessions = make(map[[AppIDLength]byte]*DisconnectedSession)

	appID := &[AppIDLength]byte{0x0F}
	require.NotPanics(t, func() {
		d.deliverARQResponse(appID, nil, &Response{AppID: appID})
	}, "a terminal outcome with no connection must not panic")

	// A nil listener is the other way this can be reached during shutdown.
	d.listener = nil
	require.NotPanics(t, func() {
		d.deliverARQResponse(appID, nil, &Response{AppID: appID})
	}, "nor with no listener at all")
}
