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
	worker.Worker `cbor:"-"`

	Priq  *queue.PriorityQueue
	NextQ Nqueue `cbor:"-"`

	Timer  *time.Timer `cbor:"-"`
	l      *sync.Mutex
	wakech chan struct{}
}

// Start starts the worker routine
func (a *TimerQueue) Start() {
	a.Go(a.worker)
}

// NewTimerQueue intantiates a new TimerQueue and starts the worker routine
func NewTimerQueue(nextQueue Nqueue) *TimerQueue {
	a := &TimerQueue{
		NextQ:  nextQueue,
		Timer:  time.NewTimer(0),
		Priq:   queue.New(),
		wakech: make(chan struct{}),
		l:      new(sync.Mutex),
	}
	return a
}

// Push adds a message to the TimerQueue
func (a *TimerQueue) Push(i Item) {
	a.l.Lock()
	a.Priq.Enqueue(i.Priority(), i)
	a.l.Unlock()
	select {
	case a.wakech <- struct{}{}:
	case <-a.HaltCh():
		// don't block at shutdown
	}
}

// pop top item from queue and forward to next queue
func (a *TimerQueue) forward() {
	a.l.Lock()
	m := heap.Pop(a.Priq)
	a.l.Unlock()
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
		a.l.Lock()
		if m := a.Priq.Peek(); m != nil {
			// Figure out if the message needs to be handled now.
			until := time.Until(time.Unix(0, int64(m.Priority)))
			if until == 0 {
				a.l.Unlock()
				a.forward()
				continue
			} else {
				c = time.After(until)
			}
		}
		a.l.Unlock()
		select {
		case <-a.HaltCh():
			return
		case <-c:
			a.forward()
		case <-a.wakech:
		}
	}
}
