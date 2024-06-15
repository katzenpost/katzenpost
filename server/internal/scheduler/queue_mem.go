// SPDX-FileCopyrightText: Copyright (C) 2017, 2018  Yawning Angel.
// SPDX-License-Identifier: AGPL 3.0

package scheduler

import (
	"container/heap"
	mRand "math/rand"
	"time"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/core/queue"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/packet"
	"gopkg.in/op/go-logging.v1"
)

type memoryQueue struct {
	glue glue.Glue
	log  *logging.Logger

	q     *queue.PriorityQueue
	mRand *mRand.Rand
}

func (q *memoryQueue) Halt() {
	// No cleanup to be done.
}

func (q *memoryQueue) Peek() (time.Time, *packet.Packet) {
	e := q.q.Peek()
	if e == nil {
		return time.Time{}, nil
	}

	return time.Unix(0, int64(e.Priority)), e.Value.(*packet.Packet)
}

func (q *memoryQueue) Pop() {
	heap.Pop(q.q)
}

func (q *memoryQueue) BulkEnqueue(batch []*packet.Packet) {
	now := time.Now()
	for _, pkt := range batch {
		q.doEnqueue(now.Add(pkt.Delay), pkt)
	}
}

func (q *memoryQueue) doEnqueue(prio time.Time, pkt *packet.Packet) {
	// Enqueue the packet unconditionally so that it is a
	// candidate to be dropped.
	q.q.Enqueue(uint64(prio.UnixNano()), pkt)

	// If queue limitations are enabled, check to see if the
	// queue is over capacity after the new packet was
	// inserted.
	maxCapacity := q.glue.Config().Debug.SchedulerQueueSize
	if maxCapacity > 0 && q.q.Len() > maxCapacity {
		drop := q.q.DequeueRandom(q.mRand).Value.(*packet.Packet)
		q.log.Debugf("Queue size limit reached, discarding: %v", drop.ID)
		drop.Dispose()
	}
}

func newMemoryQueue(glue glue.Glue, log *logging.Logger) queueImpl {
	q := &memoryQueue{
		glue:  glue,
		log:   log,
		q:     queue.New(),
		mRand: rand.NewMath(),
	}
	return q
}
