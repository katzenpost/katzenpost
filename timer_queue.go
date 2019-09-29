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
	"fmt"
	"sync"
	"time"

	"github.com/katzenpost/core/queue"
	"github.com/katzenpost/core/worker"
)

type Item interface {
	Priority() uint64
}

type nqueue interface {
	Push(Item) error
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
func (a *TimerQueue) Push(i Item) {
	a.Lock()
	a.priq.Enqueue(i.Priority(), i)
	a.Unlock()
	a.Signal()
}

// Remove removes a Message from the TimerQueue
func (a *TimerQueue) Remove(i Item) error {
	a.Lock()
	defer a.Unlock()
	if mo := a.priq.Peek(); mo != nil {
		if mo.Value.(Item).Priority() == i.Priority() {
			_ = a.priq.Pop()
			if a.priq.Len() > 0 {
				a.Signal()
			}
		} else {
			priority := mo.Value.(Item).Priority()
			mo := a.priq.RemovePriority(priority)
			if mo == nil {
				return fmt.Errorf("failed to remove item with priority %d", priority)
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
	m := a.priq.Pop()

	a.Unlock()
	if m == nil {
		return
	}
	item := m.(*queue.Entry).Value.(Item)
	if err := a.nextQ.Push(item); err != nil {
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
