// SPDX-License-Identifier: AGPL-3.0-only

package queue

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTimerQueueCancelBeforeTheWorkerTakesIt(t *testing.T) {
	t.Parallel()
	q := NewTimerQueue(func(interface{}) {})
	t.Cleanup(q.Halt)

	a, b := new(int), new(int)
	far := uint64(time.Now().Add(time.Hour).UnixNano())
	q.Push(far, a)
	q.Push(far, b)
	require.Equal(t, 2, q.PushChLen())
	require.Equal(t, 0, q.Len())

	require.True(t, q.Cancel(a), "an entry the worker has not taken yet is cancellable")
	require.False(t, q.Cancel(a), "it is gone, so a second cancel finds nothing")
	require.Equal(t, 1, q.Len()+q.PushChLen(), "the other entry is still queued")
	require.True(t, q.Cancel(b), "and is itself cancellable")
	require.Equal(t, 0, q.Len()+q.PushChLen())
}

func TestTimerQueueCancelRacesTheWorker(t *testing.T) {
	t.Parallel()
	q := NewTimerQueue(func(interface{}) {})
	q.Start()
	t.Cleanup(q.Halt)

	far := uint64(time.Now().Add(time.Hour).UnixNano())
	for i := 0; i < 200; i++ {
		v := new(int)
		q.Push(far, v)
		require.True(t, q.Cancel(v),
			"a cancel must find the entry whether the worker has taken it or not")
	}
	require.Equal(t, 0, q.Len()+q.PushChLen())
}

func TestTimerQueueCancelLeavesTheRestSchedulable(t *testing.T) {
	t.Parallel()
	fired := make(chan interface{}, 2)
	q := NewTimerQueue(func(v interface{}) { fired <- v })
	t.Cleanup(q.Halt)

	cancelled, kept := new(int), new(int)
	q.Push(uint64(time.Now().Add(time.Hour).UnixNano()), cancelled)
	q.Push(uint64(time.Now().Add(10*time.Millisecond).UnixNano()), kept)
	require.True(t, q.Cancel(cancelled))

	q.Start()
	select {
	case got := <-fired:
		require.Equal(t, kept, got, "only the entry that was not cancelled fires")
	case <-time.After(10 * time.Second):
		t.Fatal("an entry a cancel moved out of the pending list was never scheduled")
	}
	select {
	case got := <-fired:
		t.Fatalf("a cancelled entry fired: %v", got)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestTimerQueueCancelDoesNotDispatchTheNextEarly(t *testing.T) {
	t.Parallel()
	fired := make(chan interface{}, 2)
	q := NewTimerQueue(func(v interface{}) { fired <- v })
	q.Start()
	t.Cleanup(q.Halt)

	a, b := new(int), new(int)
	start := time.Now()
	q.Push(uint64(start.Add(500*time.Millisecond).UnixNano()), a)
	q.Push(uint64(start.Add(time.Hour).UnixNano()), b)
	require.Eventually(t, func() bool { return q.Len() == 2 }, 250*time.Millisecond, time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	require.True(t, q.Cancel(a))

	select {
	case got := <-fired:
		t.Fatalf("an entry due in an hour ran %v after start, its neighbour having been cancelled (is b: %v)", time.Since(start), got == b)
	case <-time.After(time.Until(start.Add(time.Second))):
	}
}
