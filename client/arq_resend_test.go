// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/queue"
)

// TestEnqueueResendNeverLoses verifies that a flood of ARQ timer fires
// never loses a retry. With per-client resend queues, enqueueResend drops
// to the backing arqTimerQueue when the per-client queue is full — the
// timer re-fires later — so every SURB ID that the ARQ timer sees is
// eventually delivered to the client's resendCh or re-armed on the timer.
func TestEnqueueResendNeverLoses(t *testing.T) {
	l := newSchedulerListener()
	const resendBuf = 2
	a := newTestIncomingConn(0x0A, 8, resendBuf)
	l.testRegister(a)

	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	d := &Daemon{
		logbackend:   logBackend,
		log:          logBackend.GetLogger("test"),
		listener:     l,
		replyLock:    new(sync.Mutex),
		arqSurbIDMap: make(map[[sphinxConstants.SURBIDLength]byte]*ARQMessage),
	}

	var rearmed atomic.Int32
	d.arqTimerQueue = queue.NewTimerQueue(func(interface{}) {
		rearmed.Add(1)
	})

	const numResends = 100
	for i := 0; i < numResends; i++ {
		var surbID [sphinxConstants.SURBIDLength]byte
		surbID[0] = byte(i)
		surbID[1] = byte(i >> 8)
		d.replyLock.Lock()
		d.arqSurbIDMap[surbID] = &ARQMessage{AppID: a.appID, SURBID: &surbID}
		d.replyLock.Unlock()
	}

	// Fire enqueueResend for every SURB ID we registered. The first
	// resendBuf land in the client's resendCh; the rest are re-armed on
	// arqTimerQueue so they'll retry after the backoff.
	for k := range d.arqSurbIDMap {
		surbID := k
		d.enqueueResend(&surbID)
	}

	// resendCh is saturated.
	require.Len(t, a.resendCh, resendBuf)
	// Every remaining attempt must be queued for retry on the timer —
	// nothing silently dropped. With the TimerQueue worker unstarted, the
	// re-armed items sit in the push channel rather than the internal heap.
	require.Equal(t, numResends-resendBuf, d.arqTimerQueue.PushChLen(),
		"all resends that could not enter resendCh must be re-armed, none dropped")
}
