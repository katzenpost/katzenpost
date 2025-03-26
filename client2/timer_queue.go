// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only
package client2

import (
	"math"
	"sync"
	"time"

	"github.com/katzenpost/katzenpost/core/queue"
	"github.com/katzenpost/katzenpost/core/worker"
)

type pushedItem struct {
	priority uint64
	value    interface{}
}

type TimerQueue struct {
	worker.Worker

	queue  *queue.PriorityQueue
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
		queue:  queue.New(),
		action: action,
		pushCh: make(chan *pushedItem, 100),
	}
}

func (t *TimerQueue) Start() {
	t.Go(t.worker)
}

func (t *TimerQueue) Peek() *queue.Entry {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.queue.Peek()
}

func (t *TimerQueue) Pop() interface{} {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.queue.Pop()
}

func (t *TimerQueue) Len() int {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.queue.Len()
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
			t.queue.Pop()
			t.mutex.Unlock()
			if m != nil {
				t.Go(func() {
					t.action(m.Value)
				})
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
				t.queue.Pop()
				t.mutex.Unlock()
				t.Go(func() {
					t.action(m.Value)
				})
				continue
			} else {
				timer.Reset(time.Duration(timeLeft))
				t.mutex.Unlock()
				break
			}
		}
	}
}
