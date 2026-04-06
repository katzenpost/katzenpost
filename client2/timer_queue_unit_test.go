// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

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
