// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only
package client2

import (
	"sync"
	"time"

	"github.com/katzenpost/katzenpost/core/queue"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/worker"
)

type TimerQueue struct {
	worker.Worker

	queue  *queue.PriorityQueue
	timer  *time.Timer
	mutex  sync.RWMutex
	action func(interface{})
}

func NewTimerQueue(action func(interface{})) *TimerQueue {
	return &TimerQueue{
		timer:  time.NewTimer(0),
		queue:  queue.New(),
		action: action,
	}
}

func (t *TimerQueue) Start() {
	t.Go(t.worker)
}

func (t *TimerQueue) Push(priority uint64, surbID *[sConstants.SURBIDLength]byte) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.queue.Enqueue(priority, surbID)
}

func (t *TimerQueue) Len() int {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.queue.Len()
}

func (t *TimerQueue) worker() {
	for {
		var waitCh <-chan time.Time
		t.mutex.RLock()

		m := t.queue.Peek()
		if m != nil {
			// Figure out if the message needs to be handled now.
			timeLeft := int64(m.Priority) - time.Now().UnixNano()
			if timeLeft < 0 || m.Priority < uint64(time.Now().UnixNano()) {
				t.mutex.RUnlock()
				t.mutex.Lock()
				t.queue.Pop()
				t.mutex.Unlock()
				t.action(m.Value)
				continue
			} else {
				waitCh = time.After(time.Duration(timeLeft))
			}
		}
		t.mutex.RUnlock()
		select {
		case <-t.HaltCh():
			return
		case <-waitCh:
			t.mutex.Lock()
			t.queue.Pop()
			t.mutex.Unlock()
			t.action(m.Value)
		}
	}
}
