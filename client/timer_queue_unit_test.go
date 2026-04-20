// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTimerQueuePeekPopLen(t *testing.T) {
	noop := func(interface{}) {}
	q := NewTimerQueue(noop)
	// Don't start the worker — test the queue data structure directly

	require.Equal(t, 0, q.Len())
	require.Nil(t, q.Peek())
	require.Nil(t, q.Pop())

	// Enqueue directly (bypassing Push/pushCh/worker)
	q.queue.Enqueue(300, "third")
	q.queue.Enqueue(100, "first")
	q.queue.Enqueue(200, "second")

	require.Equal(t, 3, q.Len())

	// Peek returns lowest priority without removing
	entry := q.Peek()
	require.NotNil(t, entry)
	require.Equal(t, "first", entry.Value)
	require.Equal(t, uint64(100), entry.Priority)
	require.Equal(t, 3, q.Len())

	// Pop returns *queue.Entry with lowest priority first
	raw := q.Pop()
	require.NotNil(t, raw)
	require.Equal(t, 2, q.Len())

	raw = q.Pop()
	require.NotNil(t, raw)
	raw = q.Pop()
	require.NotNil(t, raw)
	require.Equal(t, 0, q.Len())
	require.Nil(t, q.Pop())
}

func TestTimerQueueCancelRemovesMatchingEntry(t *testing.T) {
	noop := func(interface{}) {}
	q := NewTimerQueue(noop)
	// Don't start the worker — test the heap primitive directly.

	q.queue.Enqueue(100, "a")
	q.queue.Enqueue(200, "b")
	q.queue.Enqueue(300, "c")
	require.Equal(t, 3, q.Len())

	require.True(t, q.Cancel("b"))
	require.Equal(t, 2, q.Len())

	// Walk remaining entries via Peek; "b" must be gone.
	remaining := make([]interface{}, 0, 2)
	for q.Len() > 0 {
		e := q.Peek()
		require.NotNil(t, e)
		remaining = append(remaining, e.Value)
		q.Pop()
	}
	require.ElementsMatch(t, []interface{}{"a", "c"}, remaining)
}

func TestTimerQueueCancelAbsentValueReturnsFalse(t *testing.T) {
	noop := func(interface{}) {}
	q := NewTimerQueue(noop)

	q.queue.Enqueue(100, "a")
	q.queue.Enqueue(200, "b")

	require.False(t, q.Cancel("never-pushed"))
	require.Equal(t, 2, q.Len())
}

func TestTimerQueueCancelPointerIdentity(t *testing.T) {
	noop := func(interface{}) {}
	q := NewTimerQueue(noop)

	// Two distinct pointers to byte arrays with identical contents.
	p1 := &[4]byte{1, 2, 3, 4}
	p2 := &[4]byte{1, 2, 3, 4}
	require.NotSame(t, p1, p2)

	q.queue.Enqueue(100, p1)
	q.queue.Enqueue(200, p2)
	require.Equal(t, 2, q.Len())

	require.True(t, q.Cancel(p1))
	require.Equal(t, 1, q.Len())

	// The survivor must be p2 specifically, proving Cancel used
	// pointer identity and not content equality.
	entry := q.Peek()
	require.NotNil(t, entry)
	require.Same(t, p2, entry.Value)
}

func TestTimerQueueCancelDoesNotFireAction(t *testing.T) {
	var fired atomic.Int32
	action := func(interface{}) {
		fired.Add(1)
	}

	q := NewTimerQueue(action)
	q.Start()
	defer func() {
		go q.Halt()
		q.Wait()
	}()

	// Deadline 300ms out — long enough to Cancel before the worker
	// would ordinarily fire.
	deadline := uint64(time.Now().Add(300 * time.Millisecond).UnixNano())
	q.Push(deadline, "doomed")

	// Wait for the worker to drain pushCh into the heap before cancelling.
	require.Eventually(t, func() bool { return q.Len() == 1 }, time.Second, 5*time.Millisecond)

	require.True(t, q.Cancel("doomed"))
	require.Equal(t, 0, q.Len())

	// Give the worker comfortably past the original deadline; if the
	// action fires, the Cancel failed.
	time.Sleep(600 * time.Millisecond)
	require.Equal(t, int32(0), fired.Load())
}

func TestTimerQueueWorkerFiresCallback(t *testing.T) {
	var fired atomic.Int32
	done := make(chan struct{})

	action := func(val interface{}) {
		if fired.Add(1) == 1 {
			close(done)
		}
	}

	q := NewTimerQueue(action)
	q.Start()
	defer func() {
		go q.Halt()
		q.Wait()
	}()

	// Push item with past deadline so it fires immediately
	q.Push(uint64(time.Now().Add(-time.Second).UnixNano()), "expired")

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("callback did not fire within 5 seconds")
	}

	require.Equal(t, int32(1), fired.Load())
}
