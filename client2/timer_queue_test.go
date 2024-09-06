// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"

	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

func TestTimerQueueHalt(t *testing.T) {
	t.Parallel()
	noop := func(ignored interface{}) {
		t.Log("action")
	}
	q := NewTimerQueue(noop)
	q.Start()
	surbID := [sConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbID[:])
	require.NoError(t, err)
	go q.Halt()
	q.Wait()
}

func TestTimerQueuePush(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	surbidMap := make(map[[sConstants.SURBIDLength]byte]time.Time)

	actionsLock := new(sync.RWMutex)
	actions := 0
	numItems := 10
	actionsDoneCh := make(chan struct{}, 0)
	noop := func(rawSurbId interface{}) {

		surbId, ok := rawSurbId.(*[sConstants.SURBIDLength]byte)
		if !ok {
			panic("not a surb id")
		}

		t.Log("action")

		actionsLock.Lock()
		actions += 1
		arrivalTime := surbidMap[*surbId]
		actionsLock.Unlock()

		now := time.Now()
		delta := now.Sub(arrivalTime)

		// Fail test if any of the queue items are more than halt a second late.
		require.False(t, delta > (500*time.Millisecond))

		if actions == numItems {
			actionsDoneCh <- struct{}{}
		}
	}
	q := NewTimerQueue(noop)
	q.Start()

	require.Equal(t, 0, q.Len())

	itemDelay := 4 * time.Second

	for i := 0; i < numItems; i++ {
		surbID := [sConstants.SURBIDLength]byte{}
		_, err := io.ReadFull(rand.Reader, surbID[:])
		assert.NoError(err)

		rtt := itemDelay
		duration := rtt
		replyArrivalTime := time.Now().Add(duration)
		surbidMap[surbID] = replyArrivalTime
		priority := uint64(replyArrivalTime.UnixNano())

		t.Logf("Push %d", i)
		q.Push(priority, &surbID)
	}

	<-actionsDoneCh

	actionsLock.RLock()
	queuedItems := numItems - actions
	actionsLock.RUnlock()

	require.Equal(t, queuedItems, q.Len())
	t.Logf("queuedItems %d", queuedItems)

	require.Equal(t, 0, queuedItems)

	t.Logf("queue length %d", q.Len())

	go q.Halt()
	q.Wait()
}
