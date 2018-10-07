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

package session

import (
	"errors"
)

const MAX_QUEUE_SIZE = 40

var QueueFullError = errors.New("Error, queue is full.")
var QueueEmptyError = errors.New("Error, queue is empty.")

type EgressQueue interface {
	Peek() (*MessageRef, error)
	Pop() (*MessageRef, error)
	Push(*MessageRef) error
}

type Queue struct {
	content   [MAX_QUEUE_SIZE]MessageRef
	readHead  int
	writeHead int
	len       int
}

func (q *Queue) Push(e *MessageRef) error {
	if q.len >= MAX_QUEUE_SIZE {
		return QueueFullError
	}
	q.content[q.writeHead] = *e
	q.writeHead = (q.writeHead + 1) % MAX_QUEUE_SIZE
	q.len++
	return nil
}

func (q *Queue) Pop() (*MessageRef, error) {
	if q.len <= 0 {
		return nil, QueueEmptyError
	}
	result := q.content[q.readHead]
	q.content[q.readHead] = MessageRef{}
	q.readHead = (q.readHead + 1) % MAX_QUEUE_SIZE
	q.len--
	return &result, nil
}

func (q *Queue) Peek() (*MessageRef, error) {
	if q.len <= 0 {
		return nil, QueueEmptyError
	}
	result := q.content[q.readHead]
	return &result, nil
}
