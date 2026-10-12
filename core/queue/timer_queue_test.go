// SPDX-License-Identifier: AGPL-3.0-only

package queue

import (
	"sync/atomic"
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

func TestTimerQueueHaltLeavesUnrunItemsPoppable(t *testing.T) {
	t.Parallel()
	for round := 0; round < 200; round++ {
		var ran atomic.Int64
		q := NewTimerQueue(func(interface{}) { ran.Add(1) })
		q.EnqueueDirect(0, new(int))
		q.Start()
		q.Push(0, new(int))
		q.Halt()

		popped := 0
		for q.Pop() != nil {
			popped++
		}
		require.Equal(t, 2, int(ran.Load())+popped+q.PushChLen(),
			"round %d: ran %d, popped %d, pending %d", round, ran.Load(), popped, q.PushChLen())
	}
}

func TestTimerQueuePopReturnsAJustPushedEntry(t *testing.T) {
	t.Parallel()
	q := NewTimerQueue(func(interface{}) {})
	t.Cleanup(q.Halt)

	early, late := new(int), new(int)
	q.EnqueueDirect(2, late)
	q.Push(1, early)

	for _, want := range []*int{early, late} {
		e, ok := q.Pop().(*Entry)
		require.True(t, ok, "Pop found nothing although an entry was pushed")
		require.Same(t, want, e.Value, "Pop skipped the entry that was pushed but not yet in the heap")
	}
	require.Nil(t, q.Pop())
	require.Equal(t, 0, q.Len()+q.PushChLen())
}

func TestTimerQueueDispatchIsBounded(t *testing.T) {
	t.Parallel()
	const n = 50
	var inFlight atomic.Int64
	started := make(chan struct{}, n)
	var q *TimerQueue
	q = NewTimerQueue(func(interface{}) {
		inFlight.Add(1)
		defer inFlight.Add(-1)
		started <- struct{}{}
		<-q.HaltCh()
	})
	for i := 0; i < n; i++ {
		q.Push(0, new(int))
	}
	q.Start()
	t.Cleanup(q.Halt)

	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("no due entry was dispatched")
	}
	select {
	case <-started:
		t.Fatalf("a second action started while the first was still running, %d in flight", inFlight.Load())
	case <-time.After(200 * time.Millisecond):
	}
	require.Equal(t, int64(1), inFlight.Load())
	require.Equal(t, n-1, q.Len()+q.PushChLen(), "entries not yet run must stay queued")
}
