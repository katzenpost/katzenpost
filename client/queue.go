// queue.go - Client egress queue.
// Copyright (C) 2018  David Stainton.
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
	"errors"
	"sync"

	"github.com/katzenpost/client/constants"
)

// ErrQueueFull is the error issued when the queue is full.
var ErrQueueFull = errors.New("queue is full")

// ErrQueueEmpty is the error issued when the queue is empty.
var ErrQueueEmpty = errors.New("queue is empty")

// EgressQueue is the egress queue interface.
type EgressQueue interface {

	// Peek returns the next queue item without modifying the queue.
	Peek() (Item, error)

	// Pop pops the next item off the queue.
	Pop() (Item, error)

	// Push pushes the item onto the queue.
	Push(Item) error
}

// Queue is our in-memory queue implementation used as our egress FIFO queue
// for messages sent by the client.
type Queue struct {
	sync.Mutex
	content   [constants.MaxEgressQueueSize]Item
	readHead  int
	writeHead int
	len       int
}

// Push pushes the given message ref onto the queue and returns nil
// on success, otherwise an error is returned.
func (q *Queue) Push(e Item) error {
	q.Lock()
	defer q.Unlock()
	if q.len >= constants.MaxEgressQueueSize {
		return ErrQueueFull
	}
	q.content[q.writeHead] = e
	q.writeHead = (q.writeHead + 1) % constants.MaxEgressQueueSize
	q.len++
	return nil
}

// Pop pops the next message ref off the queue and returns nil
// upon success, otherwise an error is returned.
func (q *Queue) Pop() (Item, error) {
	q.Lock()
	defer q.Unlock()
	if q.len <= 0 {
		return nil, ErrQueueEmpty
	}
	result := q.content[q.readHead]
	q.content[q.readHead] = &Message{}
	q.readHead = (q.readHead + 1) % constants.MaxEgressQueueSize
	q.len--
	return result, nil
}

// Peek returns the next message ref from the queue without
// modifying the queue.
func (q *Queue) Peek() (Item, error) {
	q.Lock()
	defer q.Unlock()
	if q.len <= 0 {
		return nil, ErrQueueEmpty
	}
	result := q.content[q.readHead]
	return result, nil
}
