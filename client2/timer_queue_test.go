//go:build time

// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	actionsLock := new(sync.RWMutex)
	actions := 0
	noop := func(ignored interface{}) {
		t.Log("action")
		actionsLock.Lock()
		actions += 1
		actionsLock.Unlock()
	}
	q := NewTimerQueue(noop)
	q.Start()

	require.Equal(t, 0, q.Len())

	numItems := 10
	for i := 0; i < numItems; i++ {
		surbID := [sConstants.SURBIDLength]byte{}
		_, err := io.ReadFull(rand.Reader, surbID[:])
		assert.NoError(err)

		rtt := time.Millisecond * 50
		duration := rtt
		replyArrivalTime := time.Now().Add(duration)
		priority := uint64(replyArrivalTime.UnixNano())
		t.Logf("Push %d", i)
		q.Push(priority, &surbID)
	}
	require.NotEqual(t, 0, q.Len())
	<-time.After(1 * time.Second)

	actionsLock.RLock()
	queuedItems := numItems - actions
	actionsLock.RUnlock()
	require.Equal(t, queuedItems, q.Len())
	require.Equal(t, 0, queuedItems)

	t.Logf("queue length %d", q.Len())

	go q.Halt()
	q.Wait()
}
