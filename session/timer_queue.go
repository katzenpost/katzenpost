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
	"bytes"
	"fmt"
	"sync"
	"time"

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

	priorityMap map[MessageID]uint64
}

// NewTimerQueue intantiates a new TimerQueue and starts the worker routine
func NewTimerQueue(nextQueue nqueue) *TimerQueue {
	a := &TimerQueue{
		nextQ:       nextQueue,
		timer:       time.NewTimer(0),
		priq:        queue.New(),
		priorityMap: make(map[MessageID]uint64),
	}
	a.L = new(sync.Mutex)
	a.Go(a.worker)
	return a
}

// Push adds a message to the TimerQueue
func (a *TimerQueue) Push(priority uint64, m *Message) {
	a.Lock()
	a.priq.Enqueue(priority, m)
	a.priorityMap[m.ID] = priority
	a.Unlock()
	a.Signal()
}

// Remove removes a Message from the TimerQueue
func (a *TimerQueue) Remove(id MessageID) error {
	a.Lock()
	defer a.Unlock()
	if mo := a.priq.Peek(); mo != nil {
		if bytes.Equal(mo.Value.(*Message).ID[:], id[:]) {
			_ = a.priq.Pop()
			if a.priq.Len() > 0 {
				a.Signal()
			}
		} else {
			prio, ok := a.priorityMap[id]
			if !ok {
				return fmt.Errorf("Failed to remove, message ID %v not found", id)
			}
			delete(a.priorityMap, id)
			mo := a.priq.RemovePriority(prio)
			if mo == nil {
				return fmt.Errorf("Failed to remove %v", id)
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
	message := m.(*queue.Entry).Value.(*Message)
	delete(a.priorityMap, message.ID)

	if err := a.nextQ.Push(message); err != nil {
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
