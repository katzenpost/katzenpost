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

// A cancel and a terminal reply both try to end the same operation. Exactly one
// of them may answer the original query, so the claim has to be exclusive.
func TestClaimARQTerminalIsExclusive(t *testing.T) {
	l := newSchedulerListener()
	d, _ := newARQTestDaemon(t, l)
	appID := &[AppIDLength]byte{0x0A}
	m := trackARQMessage(d, appID)

	require.True(t, d.claimARQTerminal(m), "the first claim takes the operation")
	require.False(t, d.claimARQTerminal(m), "a second claim must not answer the query again")
	require.Equal(t, 0, arqTracked(d, m), "a claimed operation is removed from both maps")
}

// pigeonhole.md: clients MUST resend identical CourierEnvelope bodies until they
// receive a reply. A thin client that is away within its grace period has not
// received one, so the operation must survive and stay scheduled.
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

// The same rule applies when a reply arrives while the client is away:
// handleReply has already cancelled the retry, so returning without
// rescheduling would leave the operation tracked and never resent.
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

// The claim has to be exclusive under contention, not merely in sequence: a
// cancel and a terminal reply can run on different goroutines, and exactly one of
// them may answer the original query. Running the two concurrently is what
// distinguishes an exclusive claim from a check followed by a delete.
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
