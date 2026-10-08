// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package queue

import (
	"math"
	"sync"
	"time"

	"github.com/katzenpost/katzenpost/core/worker"
)

type pushedItem struct {
	priority uint64
	value    interface{}
}

type TimerQueue struct {
	worker.Worker

	queue  *PriorityQueue
	timer  *time.Timer
	mutex  sync.RWMutex
	action func(interface{})

	pending []*pushedItem
	wakeCh  chan struct{}
}

func NewTimerQueue(action func(interface{})) *TimerQueue {
	return &TimerQueue{
		timer:  time.NewTimer(0),
		queue:  New(),
		action: action,
		wakeCh: make(chan struct{}, 1),
	}
}

func (t *TimerQueue) Start() {
	t.Go(t.worker)
}

func (t *TimerQueue) Peek() *Entry {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.queue.Peek()
}

func (t *TimerQueue) Pop() interface{} {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.mergePendingLocked()
	return t.queue.Dequeue()
}

func (t *TimerQueue) mergePendingLocked() {
	for _, item := range t.pending {
		t.queue.Enqueue(item.priority, item.value)
	}
	t.pending = nil
}

func (t *TimerQueue) Len() int {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.queue.Len()
}

// Cancel removes the first entry whose Value is equal to the supplied value
// (Go == comparison, which for pointer values is pointer identity), whether
// the worker has moved it into the heap yet or not, and returns true if an
// entry was removed. Entries already popped by the worker are not
// cancellable; callers that need to defend against the
// popped-but-action-not-yet-run race must handle that at the action callback.
func (t *TimerQueue) Cancel(value interface{}) bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	for i := 0; i < t.queue.Len(); i++ {
		e := t.queue.PeekIndex(i)
		if e == nil {
			break
		}
		if e.Value == value {
			t.queue.DequeueIndex(i)
			return true
		}
	}
	for i, item := range t.pending {
		if item.value == value {
			t.pending = append(t.pending[:i], t.pending[i+1:]...)
			return true
		}
	}
	return false
}

func (t *TimerQueue) Push(priority uint64, value interface{}) {
	select {
	case <-t.HaltCh():
		return
	default:
	}
	t.mutex.Lock()
	t.pending = append(t.pending, &pushedItem{
		priority: priority,
		value:    value,
	})
	t.mutex.Unlock()
	select {
	case t.wakeCh <- struct{}{}:
	default:
	}
}

// PushChLen reports the number of items Push has accepted that have not yet
// been moved into the heap. Intended for tests that wish to assert "items
// were pushed but the worker has not yet drained them"; production callers
// should not depend on this value.
func (t *TimerQueue) PushChLen() int {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return len(t.pending)
}

// EnqueueDirect inserts an entry directly into the internal heap,
// bypassing the pending list and any worker buffering. Intended for
// tests that wish to populate the heap without running the worker.
// Holds the queue's write lock for the duration of the call.
func (t *TimerQueue) EnqueueDirect(priority uint64, value interface{}) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.queue.Enqueue(priority, value)
}

func (t *TimerQueue) worker() {
	timer := time.NewTimer(math.MaxInt64)
	defer timer.Stop()

	for {
		var timerFired bool

		select {
		case <-t.HaltCh():
			return
		case <-timer.C:
			timerFired = true
		case <-t.wakeCh:
			t.mutex.Lock()
			t.mergePendingLocked()
			t.mutex.Unlock()
		}

		if !timerFired && !timer.Stop() {
			select {
			case <-timer.C:
			case <-t.HaltCh():
				return
			}
		}

		for {
			t.mutex.Lock()
			select {
			case <-t.HaltCh():
				t.mutex.Unlock()
				return
			default:
			}
			m := t.queue.Peek()

			if m == nil {
				// The queue is empty, just reschedule for the max duration,
				// when there are messages to schedule, we'll get woken up.
				timer.Reset(math.MaxInt64)
				t.mutex.Unlock()
				break
			}

			// Figure out if the message needs to be handled now.
			timeLeft := int64(m.Priority) - time.Now().UnixNano()
			if timeLeft < 0 || m.Priority < uint64(time.Now().UnixNano()) {
				t.queue.Dequeue()
				t.mutex.Unlock()
				value := m.Value
				t.Go(func() { t.action(value) })
				continue
			} else {
				timer.Reset(time.Duration(timeLeft))
				t.mutex.Unlock()
				break
			}
		}
	}
}
