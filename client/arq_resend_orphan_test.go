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
	"github.com/katzenpost/katzenpost/pigeonhole"
)

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

	d.listener = nil
	require.NotPanics(t, func() {
		d.deliverARQResponse(appID, nil, &Response{AppID: appID})
	}, "nor with no listener at all")
}

func TestDeliverARQResponseFindsAReconnectedClient(t *testing.T) {
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)

	d := &Daemon{
		logbackend: logBackend,
		log:        logBackend.GetLogger("test"),
		listener:   newSchedulerListener(),
		replyLock:  new(sync.Mutex),
	}
	d.listener.log = logBackend.GetLogger("listener")
	d.listener.disconnectedSessions = make(map[[AppIDLength]byte]*DisconnectedSession)

	conn := newTestIncomingConn(0x11, 1, 1)
	conn.sendWake = make(chan struct{}, 1)
	d.listener.testRegister(conn)

	d.deliverARQResponse(conn.appID, nil, &Response{AppID: conn.appID})

	conn.sendQueueMu.Lock()
	queued := len(conn.sendQueue)
	conn.sendQueueMu.Unlock()
	require.Equal(t, 1, queued,
		"a client that reconnected before the outcome was delivered must still be answered")
}

func TestMalformedCopyReplyAnswersInsteadOfResending(t *testing.T) {
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)

	var rearmed atomic.Int32
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
	d.arqTimerQueue = queue.NewTimerQueue(func(interface{}) { rearmed.Add(1) })
	t.Cleanup(func() { d.arqTimerQueue.Halt() })

	conn := newTestIncomingConn(0x12, 1, 1)
	conn.sendWake = make(chan struct{}, 1)
	d.listener.testRegister(conn)

	surbID := &[sphinxConstants.SURBIDLength]byte{}
	copy(surbID[:], []byte("malformed-copy01"))
	envHash := &[32]byte{}
	envHash[0] = 0x12
	m := &ARQMessage{AppID: conn.appID, SURBID: surbID, EnvelopeHash: envHash}
	d.replyLock.Lock()
	d.arqSurbIDMap[*surbID] = m
	d.arqEnvelopeHashMap[*envHash] = surbID
	d.replyLock.Unlock()

	d.handleCopyCommandARQReply(m, &pigeonhole.CourierQueryReply{ReplyType: 0}, conn)

	conn.sendQueueMu.Lock()
	queued := len(conn.sendQueue)
	conn.sendQueueMu.Unlock()
	require.Equal(t, 1, queued, "a reply the courier mis-framed must answer the caller")
	require.Equal(t, 0, d.arqTimerQueue.PushChLen()+int(rearmed.Load()),
		"and must not schedule a resend that would mis-frame the same way")
	d.replyLock.Lock()
	require.Empty(t, d.arqSurbIDMap)
	require.Empty(t, d.arqEnvelopeHashMap)
	d.replyLock.Unlock()
}
