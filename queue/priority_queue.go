// priority_queue.go - Min-Heap based priority queue.
// Copyright (C) 2017, 2018  David Anthony Stainton, Yawning Angel
//
// This was inspired by the priority queue example in the godocs:
// https://golang.org/pkg/container/heap/
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

// Package queue implements a priority queue.
package queue

import (
	"container/heap"
	"math/rand"
)

// Entry is a PriorityQueue entry.
type Entry struct {
	Value    interface{}
	Priority uint64
	idx      int
}

type priorityQueueImpl []*Entry

func (pq priorityQueueImpl) Len() int {
	return len(pq)
}

func (pq priorityQueueImpl) Less(i, j int) bool {
	return pq[i].Priority < pq[j].Priority
}

func (pq priorityQueueImpl) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].idx = i
	pq[j].idx = j
}

func (pq *priorityQueueImpl) Push(x interface{}) {
	n := len(*pq)
	entry := x.(*Entry)
	entry.idx = n
	*pq = append(*pq, entry)
}

func (pq *priorityQueueImpl) Pop() interface{} {
	old := *pq
	n := len(old)
	entry := old[n-1]
	entry.idx = -1
	*pq = old[0 : n-1]
	return entry
}

// PriorityQueue is a priority queue instance.
type PriorityQueue struct {
	heap priorityQueueImpl
}

// Peek returns the 0th entry (lowest priority) if any, leaving the
// PriorityQueue unaltered.  Callers MUST NOT alter the Priority of the
// returned entry.
func (q *PriorityQueue) Peek() *Entry {
	if q.Len() <= 0 {
		return nil
	}
	return q.heap[0]
}

// PeekIndex peeks at the specified index.
func (q *PriorityQueue) PeekIndex(i int) *Entry {
	if q.Len() <= 0 {
		return nil
	}
	return q.heap[i]
}

// DequeueIndex removes the specified entry from the queue.
func (q *PriorityQueue) DequeueIndex(index int) *Entry {
	if q.Len() <= 0 {
		return nil
	}
	return heap.Remove(&q.heap, index).(*Entry)
}

// FilterOnce removes the first item from the queue who's value
// is passed to the filter function and returns true.
func (q *PriorityQueue) FilterOnce(filter func(value interface{}) bool) {
	for i := 0; i < q.Len(); i++ {
		if filter(q.PeekIndex(i).Value) {
			q.DequeueIndex(i)
			break
		}
	}
}

// Pop removes and returns the 0th entry (lowest priority) if any.
func (q *PriorityQueue) Pop() *Entry {
	if q.Len() <= 0 {
		return nil
	}
	return heap.Pop(&q.heap).(*Entry)
}

// Enqueue inserts the provided value, into the queue with the specified
// priority.
func (q *PriorityQueue) Enqueue(priority uint64, value interface{}) {
	ent := &Entry{
		Value:    value,
		Priority: priority,
	}
	heap.Push(&q.heap, ent)
}

// DequeueRandom removes a random entry from the queue.
func (q *PriorityQueue) DequeueRandom(r *rand.Rand) *Entry {
	if q.Len() <= 0 {
		return nil
	}
	return heap.Remove(&q.heap, r.Intn(q.Len())).(*Entry)
}

// Remove removes and returns element from the heap with given priority
func (q *PriorityQueue) Remove(priority uint64) interface{} {
	return heap.Remove(&q.heap, int(priority))
}

// Len returns the current length of the priority queue.
func (q *PriorityQueue) Len() int {
	return q.heap.Len()
}

// New creates a new PriorityQueue.
func New() *PriorityQueue {
	q := &PriorityQueue{
		heap: make(priorityQueueImpl, 0),
	}
	heap.Init(&q.heap)
	return q
}
