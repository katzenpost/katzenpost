// timer_queue.go - Time delayed queue
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

package client

import (
	"container/heap"
	"sync"
	"time"

	"github.com/katzenpost/katzenpost/core/queue"
	"github.com/katzenpost/katzenpost/core/worker"
)

type Item interface {
	Priority() uint64
}

type Nqueue interface {
	Push(Item) error
}

// TimerQueue is a queue that delays messages before forwarding to another queue
type TimerQueue struct {
	sync.Mutex    `cbor:"-"`
	sync.Cond     `cbor:"-"`
	worker.Worker `cbor:"-"`

	Priq  *queue.PriorityQueue
	NextQ Nqueue `cbor:"-"`

	Timer  *time.Timer `cbor:"-"`
	wakech chan struct{}
}

// Start starts the worker routine
func (a *TimerQueue) Start() {
	a.Go(a.worker)
}

// NewTimerQueue intantiates a new TimerQueue and starts the worker routine
func NewTimerQueue(nextQueue Nqueue) *TimerQueue {
	a := &TimerQueue{
		NextQ: nextQueue,
		Timer: time.NewTimer(0),
		Priq:  queue.New(),
	}
	a.L = new(sync.Mutex)
	return a
}

// Push adds a message to the TimerQueue
func (a *TimerQueue) Push(i Item) {
	a.Lock()
	a.Priq.Enqueue(i.Priority(), i)
	a.Unlock()
	a.Signal()
}

// wakeupCh() returns the channel that fires upon Signal of the TimerQueue's sync.Cond
func (a *TimerQueue) wakeupCh() chan struct{} {
	if a.wakech != nil {
		return a.wakech
	}
	c := make(chan struct{})
	a.Go(func() {
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
	})
	a.wakech = c
	return c
}

// pop top item from queue and forward to next queue
func (a *TimerQueue) forward() {
	a.Lock()
	m := heap.Pop(a.Priq)
	a.Unlock()
	if m == nil {
		return
	}
	item := m.(*queue.Entry).Value.(Item)
	if err := a.NextQ.Push(item); err != nil {
		panic(err)
	}
}

func (a *TimerQueue) worker() {
	for {
		var c <-chan time.Time
		a.Lock()
		if m := a.Priq.Peek(); m != nil {
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
			a.Signal()
			return
		case <-c:
			a.forward()
		case <-a.wakeupCh():
		}
	}
}
