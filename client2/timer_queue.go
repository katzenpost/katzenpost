// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only
package client2

import (
	"container/heap"
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

	cond  *sync.Cond
	mutex sync.RWMutex
	queue *queue.PriorityQueue
	timer *time.Timer

	action func(interface{})

	wakech chan struct{}
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
		cond:   sync.NewCond(new(sync.Mutex)),
	}
}

func (t *TimerQueue) Halt() {
	t.Worker.Halt()
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
	t.mutex.Lock()
	t.queue.Enqueue(priority, value)
	t.mutex.Unlock()
	t.cond.Signal()
}

// wakeupCh() returns the channel that fires upon Signal of the TimerQueue's sync.Cond
func (t *TimerQueue) wakeupCh() chan struct{} {
	if t.wakech != nil {
		return t.wakech
	}
	c := make(chan struct{})
	go func() {
		defer close(c)
		var v struct{}
		for {
			t.cond.L.Lock()
			t.cond.Wait()
			t.cond.L.Unlock()
			select {
			case <-t.HaltCh():
				return
			case c <- v:
			}
		}
	}()
	t.wakech = c
	return c
}

// pop top item from queue and call the action
// callback with the item as the argument
func (t *TimerQueue) forward() {
	t.mutex.Lock()
	m := heap.Pop(t.queue)
	t.mutex.Unlock()
	if m == nil {
		return
	}
	t.action(m.(*queue.Entry).Value)
}

func (t *TimerQueue) worker() {
	for {
		var c <-chan time.Time
		t.mutex.Lock()
		if m := t.queue.Peek(); m != nil {
			// Figure out if the message needs to be handled now.
			timeLeft := int64(m.Priority) - time.Now().UnixNano()
			if timeLeft < 0 || m.Priority < uint64(time.Now().UnixNano()) {
				t.mutex.Unlock()
				t.forward()
				continue
			} else {
				c = time.After(time.Duration(timeLeft))
			}
		}
		t.mutex.Unlock()
		select {
		case <-t.HaltCh():
			t.cond.Signal()
			return
		case <-c:
			t.forward()
		case <-t.wakeupCh():
		}
	}
}
