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

	pushCh chan *pushedItem
}

func NewTimerQueue(action func(interface{})) *TimerQueue {
	// NOTE(david): pushCh is a buffered channel that sits between
	// the worker goroutine and the goroutine which
	// calls our Push method. It needs to be a buffered
	// channel in case a Push happens while the worker
	// isn't blocking on it's select statement's timer channel.
	return &TimerQueue{
		timer:  time.NewTimer(0),
		queue:  New(),
		action: action,
		pushCh: make(chan *pushedItem, 100),
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
	return t.queue.Dequeue()
}

func (t *TimerQueue) Len() int {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.queue.Len()
}

// Cancel removes the first queued entry whose Value is equal to the supplied
// value (Go == comparison, which for pointer values is pointer identity), and
// returns true if an entry was removed. Entries already popped by the worker
// are not cancellable; callers that need to defend against the
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
	return false
}

func (t *TimerQueue) Push(priority uint64, value interface{}) {
	select {
	case t.pushCh <- &pushedItem{
		priority: priority,
		value:    value,
	}:
	case <-t.HaltCh():
	}
}

// PushChLen reports the number of items presently buffered in the push
// channel waiting to be ingested by the worker. Intended for tests that
// wish to assert "items were pushed but the worker has not yet drained
// them"; production callers should not depend on this value.
func (t *TimerQueue) PushChLen() int {
	return len(t.pushCh)
}

// EnqueueDirect inserts an entry directly into the internal heap,
// bypassing the push channel and any worker buffering. Intended for
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

			t.mutex.Lock()
			m := t.queue.Peek()
			t.queue.Dequeue()
			t.mutex.Unlock()
			if m != nil {
				// Use a separate goroutine that respects the halt channel
				go func(value interface{}) {
					select {
					case <-t.HaltCh():
						return
					default:
						t.action(value)
					}
				}(m.Value)
			}
		case item := <-t.pushCh:
			t.mutex.Lock()
			t.queue.Enqueue(item.priority, item.value)
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
				// Use a separate goroutine that respects the halt channel
				go func(value interface{}) {
					select {
					case <-t.HaltCh():
						return
					default:
						t.action(value)
					}
				}(m.Value)
				continue
			} else {
				timer.Reset(time.Duration(timeLeft))
				t.mutex.Unlock()
				break
			}
		}
	}
}
