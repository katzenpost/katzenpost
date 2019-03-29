// timerq.go - Time delayed queue
// Copyright (C) 2018, 2019  Masala, David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package session

import (
	"fmt"
	"sync"
	"time"

	"container/heap"
	"github.com/katzenpost/core/queue"
	"github.com/katzenpost/core/worker"
)

type nqueue interface {
	Push(*Message) error
}

// TimerQueue is a queue that delays messages before forwarding to another queue
type TimerQueue struct {
	sync.Mutex
	sync.Cond
	worker.Worker

	priq  *queue.PriorityQueue
	nextQ nqueue

	timer  *time.Timer
	wakech chan struct{}
}

// NewTimerQueue intantiates a new TimerQueue and starts the worker routine
func NewTimerQueue(nextQueue nqueue) *TimerQueue {
	a := &TimerQueue{
		nextQ: nextQueue,
		timer: time.NewTimer(0),
		priq:  queue.New(),
	}
	a.L = new(sync.Mutex)
	a.Go(a.worker)
	return a
}

// Push adds a message to the TimerQueue
func (a *TimerQueue) Push(priority uint64, m interface{}) {
	a.Lock()
	a.priq.Enqueue(priority, m)
	a.Unlock()
	a.Signal()
}

// Remove removes a Message from the TimerQueue
func (a *TimerQueue) Remove(m *Message) error {
	a.Lock()
	defer a.Unlock()
	if mo := a.priq.Peek(); mo != nil {
		if mo.Value.(*Message) == m {
			heap.Pop(a.priq)
			if a.priq.Len() > 0 {
				// wake up the worker to reset the timer
				a.Signal()
			}
		} else {
			mo := a.priq.RemovePriority(mo.Priority)
			switch mo {
			case nil:
				return fmt.Errorf("Failed to remove %v", m)
			case m == mo.(*Message):
			default:
				return fmt.Errorf("Failed to remove %v", m)
			}
		}
	}
	return nil
}

// wakeupCh() returns the channel that fires upon Signal of the TimerQueue's sync.Cond
func (a *TimerQueue) wakeupCh() chan struct{} {
	if a.wakech != nil {
		return a.wakech
	}
	c := make(chan struct{})
	go func() {
		defer close(c)
		var v struct{}
		for {
			a.L.Lock()
			a.Wait()
			a.L.Unlock()
			select {
			case <-a.HaltCh():
				return
			case c <- v:
			}
		}
	}()
	a.wakech = c
	return c
}

// pop top item from queue and forward to next queue
func (a *TimerQueue) forward() {
	a.Lock()
	m := heap.Pop(a.priq)
	a.Unlock()
	if m == nil {
		return
	}

	if err := a.nextQ.Push(m.(*queue.Entry).Value.(*Message)); err != nil {
		panic(err)
	}
}

func (a *TimerQueue) worker() {
	for {
		var c <-chan time.Time
		a.Lock()
		if m := a.priq.Peek(); m != nil {
			// Figure out if the message needs to be handled now.
			timeLeft := int64(m.Priority) - time.Now().UnixNano()
			if timeLeft < 0 || m.Priority < uint64(time.Now().UnixNano()) {
				a.Unlock()
				a.forward()
				continue
			} else {
				c = time.After(time.Duration(timeLeft))
			}
		}
		a.Unlock()
		select {
		case <-a.HaltCh():
			return
		case <-c:
			a.forward()
		case <-a.wakeupCh():
		}
	}
}
