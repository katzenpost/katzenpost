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
	"fmt"
	"math/rand"
)

// Entry is a PriorityQueue entry.
type Entry struct {
	Value    interface{}
	Priority uint64
}

// PriorityQueue is a priority queue instance.
type PriorityQueue struct {
	heap []*Entry

	// mapping of priority (uint64) to map/set of indexes (map[int]bool)
	m map[uint64]map[int]bool
}

// Less implements sort.Interface Less method
func (q PriorityQueue) Less(i, j int) bool {
	return q.heap[i].Priority < q.heap[j].Priority
}

// Swap implements sort.Interface Swap method
func (q PriorityQueue) Swap(i, j int) {
	if i < 0 || j < 0 {
		return
	}
	q.heap[i], q.heap[j] = q.heap[j], q.heap[i]
	q.m[q.heap[i].Priority], q.m[q.heap[j].Priority] = q.m[q.heap[j].Priority], q.m[q.heap[i].Priority]
}

// Push implements heap.Interface Push method
func (q *PriorityQueue) Push(x interface{}) {
	fmt.Println("PUSH")
	entry := x.(*Entry)
	if q.m[entry.Priority] == nil {
		q.m[entry.Priority] = make(map[int]bool)
	}
	q.m[entry.Priority][q.Len()] = true
	q.heap = append(q.heap, entry)
}

// Pop removes and returns the 0th entry (lowest priority) if any.
func (q *PriorityQueue) Pop() interface{} {
	if q.Len() <= 0 {
		fmt.Println("POP NOOP --------------------------------")
		return nil
	}
	n := len(q.heap)
	e := q.heap[n-1]
	q.heap = q.heap[:n-1]

	index := q.Len()
	indexMap, ok := q.m[e.Priority]
	if !ok {
		panic("weird bug1")
	}
	if indexMap == nil {
		panic("weird bug2")
	}
	delete(indexMap, index)
	if len(indexMap) == 1 {
		delete(q.m, e.Priority)
	}
	return e
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
	fmt.Println("DequeueIndex start")
	if q.Len() <= 0 {
		return nil
	}
	entry := heap.Remove(q, index).(*Entry)
	fmt.Println("DequeueIndex end")
	return entry
}

// Enqueue inserts the provided value, into the queue with the specified
// priority.
func (q *PriorityQueue) Enqueue(priority uint64, value interface{}) {
	fmt.Println("Enqueue start")
	ent := &Entry{
		Value:    value,
		Priority: priority,
	}
	heap.Push(q, ent)

	fmt.Printf("map %v\n", q.m[priority])

	fmt.Println("Enqueue end")
}

// DequeueRandom removes a random entry from the queue.
func (q *PriorityQueue) DequeueRandom(r *rand.Rand) *Entry {
	if q.Len() <= 0 {
		return nil
	}
	e := heap.Remove(q, r.Intn(q.Len())).(*Entry)
	delete(q.m, e.Priority)
	return e

}

// RemovePriority removes and returns element from the heap with given priority or nil
func (q *PriorityQueue) RemovePriority(priority uint64) []*Entry {
	fmt.Printf("RemovePriority %d start\n", priority)
	indexSet, ok := q.m[priority]
	if ok {
		fmt.Printf("-------------indexSet size %d\n", len(indexSet))
		ret := make([]*Entry, len(indexSet))
		i := 0
		for index, _ := range indexSet {
			ret[i] = q.DequeueIndex(index)
			i++
		}
		fmt.Println("RemovePriority end value")
		return ret
	} else {
		fmt.Println("NO OP")
	}
	fmt.Println("RemovePriority end nil")
	return nil
}

// Remove removes and returns element from the heap with given index
func (q *PriorityQueue) Remove(index int) interface{} {
	return q.DequeueIndex(index)
}

// Len returns the current length of the priority queue.
func (q *PriorityQueue) Len() int {
	return len(q.heap)
}

// New creates a new PriorityQueue.
func New() *PriorityQueue {
	q := &PriorityQueue{
		heap: make([]*Entry, 0),
		m:    make(map[uint64]map[int]bool),
	}
	heap.Init(q)
	return q
}
