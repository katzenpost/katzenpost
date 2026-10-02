// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/queue"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

func newARQTestDaemon(t *testing.T, l *listener) (*Daemon, *atomic.Int32) {
	t.Helper()
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	d := &Daemon{
		logbackend:         logBackend,
		log:                logBackend.GetLogger("test"),
		listener:           l,
		replyLock:          new(sync.Mutex),
		arqSurbIDMap:       make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
		arqEnvelopeHashMap: make(map[[32]byte]*[sphinxConstants.SURBIDLength]byte),
	}
	var armed atomic.Int32
	d.arqTimerQueue = queue.NewTimerQueue(func(interface{}) { armed.Add(1) })
	return d, &armed
}

func trackARQMessage(d *Daemon, appID *[AppIDLength]byte) *ARQMessage {
	surbID := new([sphinxConstants.SURBIDLength]byte)
	surbID[0] = 0x11
	envHash := new([32]byte)
	envHash[0] = 0x22
	m := &ARQMessage{AppID: appID, SURBID: surbID, EnvelopeHash: envHash}
	d.replyLock.Lock()
	d.arqSurbIDMap[*surbID] = m
	d.arqEnvelopeHashMap[*envHash] = surbID
	d.replyLock.Unlock()
	return m
}

func arqTracked(d *Daemon, m *ARQMessage) int {
	d.replyLock.Lock()
	defer d.replyLock.Unlock()
	n := 0
	if _, ok := d.arqSurbIDMap[*m.SURBID]; ok {
		n++
	}
	if _, ok := d.arqEnvelopeHashMap[*m.EnvelopeHash]; ok {
		n++
	}
	return n
}

func TestClaimARQTerminalIsExclusive(t *testing.T) {
	l := newSchedulerListener()
	d, _ := newARQTestDaemon(t, l)
	appID := &[AppIDLength]byte{0x0A}
	m := trackARQMessage(d, appID)

	require.True(t, d.claimARQTerminal(m), "the first claim takes the operation")
	require.False(t, d.claimARQTerminal(m), "a second claim must not answer the query again")
	require.Equal(t, 0, arqTracked(d, m), "a claimed operation is removed from both maps")
}

func TestClaimARQTerminalCancelsThePendingTimer(t *testing.T) {
	l := newSchedulerListener()
	d, armed := newARQTestDaemon(t, l)
	appID := &[AppIDLength]byte{0x0E}
	m := trackARQMessage(d, appID)
	d.arqTimerQueue.EnqueueDirect(uint64(time.Now().Add(time.Hour).UnixNano()), m.SURBID)
	require.Equal(t, 1, d.arqTimerQueue.Len(), "the retry is armed")

	require.True(t, d.claimARQTerminal(m), "the claim takes the operation")

	require.Equal(t, 0,
		d.arqTimerQueue.Len()+d.arqTimerQueue.PushChLen()+int(armed.Load()),
		"a terminal outcome must leave no timer armed on an untracked operation")
}

func TestARQResendKeepsOperationWhileClientIsAway(t *testing.T) {
	l := newSchedulerListener()
	d, armed := newARQTestDaemon(t, l)
	appID := &[AppIDLength]byte{0x0B}
	m := trackARQMessage(d, appID)
	require.Nil(t, l.getConnection(appID), "the client is away for this test")

	d.arqDoResend(m.SURBID)

	require.Equal(t, 2, arqTracked(d, m), "an absent client must not lose the operation")
	require.Equal(t, 1, d.arqTimerQueue.PushChLen()+int(armed.Load()),
		"the operation must stay scheduled for a later retry")
}

func TestARQReplyWhileClientIsAwayReschedules(t *testing.T) {
	l := newSchedulerListener()
	d, armed := newARQTestDaemon(t, l)
	appID := &[AppIDLength]byte{0x0C}
	m := trackARQMessage(d, appID)
	require.Nil(t, l.getConnection(appID))

	d.handlePigeonholeARQReply(m, &sphinxReply{surbID: m.SURBID})

	require.Equal(t, 2, arqTracked(d, m), "the operation must survive a reply that cannot be delivered")
	require.Equal(t, 1, d.arqTimerQueue.PushChLen()+int(armed.Load()),
		"a reply that cannot be delivered must leave a retry scheduled")
}

func TestClaimARQTerminalIsExclusiveUnderContention(t *testing.T) {
	for i := 0; i < 200; i++ {
		l := newSchedulerListener()
		d, _ := newARQTestDaemon(t, l)
		appID := &[AppIDLength]byte{0x0E}
		m := trackARQMessage(d, appID)

		var claims atomic.Int32
		var wg sync.WaitGroup
		wg.Add(2)
		start := make(chan struct{})
		for j := 0; j < 2; j++ {
			go func() {
				defer wg.Done()
				<-start
				if d.claimARQTerminal(m) {
					claims.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()

		require.Equal(t, int32(1), claims.Load(),
			"exactly one of two concurrent claims may answer the query")
		require.Equal(t, 0, arqTracked(d, m), "the operation is gone from both maps")
	}
}

func TestCancelAndTerminalReplyAnswerOnlyOnce(t *testing.T) {
	answersAfter := func(t *testing.T, cancelFirst bool) int {
		t.Helper()
		l := newSchedulerListener()
		d, _ := newARQTestDaemon(t, l)
		conn := newTestIncomingConn(0x0F, 1, 1)
		conn.sendWake = make(chan struct{}, 1)
		l.testRegister(conn)

		m := trackARQMessage(d, conn.appID)
		m.QueryID = &[thin.QueryIDLength]byte{0x33}
		m.DestinationIdHash = &[32]byte{0x44}

		cancel := func() {
			d.cancelResendingEncryptedMessage(&Request{
				AppID: conn.appID,
				CancelResendingEncryptedMessage: &thin.CancelResendingEncryptedMessage{
					QueryID:      &[thin.QueryIDLength]byte{0x55},
					EnvelopeHash: m.EnvelopeHash,
				},
			})
		}
		terminal := func() {
			if d.claimARQTerminal(m) {
				d.finishARQMessage(m, conn, thin.ThinClientSuccess, nil)
			}
		}
		if cancelFirst {
			cancel()
			terminal()
		} else {
			terminal()
			cancel()
		}

		answers := 0
		conn.sendQueueMu.Lock()
		for _, r := range conn.sendQueue {
			if r.StartResendingEncryptedMessageReply != nil {
				answers++
			}
		}
		conn.sendQueueMu.Unlock()
		require.Equal(t, 0, arqTracked(d, m), "the operation is gone from both maps")
		return answers
	}

	require.Equal(t, 1, answersAfter(t, true),
		"a terminal reply after a cancel must not answer the query again")
	require.Equal(t, 1, answersAfter(t, false),
		"a cancel after a terminal reply must not answer the query again")
}

func TestCancelAndTerminalCopyReplyAnswerOnlyOnce(t *testing.T) {
	answersAfter := func(t *testing.T, cancelFirst bool) int {
		t.Helper()
		l := newSchedulerListener()
		d, _ := newARQTestDaemon(t, l)
		conn := newTestIncomingConn(0x10, 1, 1)
		conn.sendWake = make(chan struct{}, 1)
		l.testRegister(conn)

		m := trackARQMessage(d, conn.appID)
		m.QueryID = &[thin.QueryIDLength]byte{0x66}
		m.MessageType = ARQMessageTypeCopyCommand

		cancel := func() {
			d.cancelResendingCopyCommand(&Request{
				AppID: conn.appID,
				CancelResendingCopyCommand: &thin.CancelResendingCopyCommand{
					QueryID:      &[thin.QueryIDLength]byte{0x77},
					WriteCapHash: m.EnvelopeHash,
				},
			})
		}
		terminal := func() {
			if d.claimARQTerminal(m) {
				d.deliverARQResponse(m.AppID, conn, &Response{
					AppID: m.AppID,
					StartResendingCopyCommandReply: &thin.StartResendingCopyCommandReply{
						QueryID:   m.QueryID,
						ErrorCode: thin.ThinClientSuccess,
					},
				})
			}
		}
		if cancelFirst {
			cancel()
			terminal()
		} else {
			terminal()
			cancel()
		}

		answers := 0
		conn.sendQueueMu.Lock()
		for _, r := range conn.sendQueue {
			if r.StartResendingCopyCommandReply != nil {
				answers++
			}
		}
		conn.sendQueueMu.Unlock()
		require.Equal(t, 0, arqTracked(d, m), "the operation is gone from both maps")
		return answers
	}

	require.Equal(t, 1, answersAfter(t, true),
		"a terminal copy reply after a cancel must not answer the query again")
	require.Equal(t, 1, answersAfter(t, false),
		"a cancel after a terminal copy reply must not answer the query again")
}
