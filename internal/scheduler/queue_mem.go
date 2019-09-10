// queue_mem.go - Katzenpost scheduler memory queue.
// Copyright (C) 2017, 2018  Yawning Angel.
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

package scheduler

import (
	"container/heap"
	mRand "math/rand"
	"time"

	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/monotime"
	"github.com/katzenpost/core/queue"
	"github.com/katzenpost/server/internal/glue"
	"github.com/katzenpost/server/internal/packet"
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

func (q *memoryQueue) Peek() (time.Duration, *packet.Packet) {
	e := q.q.Peek()
	if e == nil {
		return 0, nil
	}

	return time.Duration(e.Priority), e.Value.(*packet.Packet)
}

func (q *memoryQueue) Pop() {
	heap.Pop(q.q)
}

func (q *memoryQueue) BulkEnqueue(batch []*packet.Packet) {
	now := monotime.Now()
	for _, pkt := range batch {
		q.doEnqueue(now+pkt.Delay, pkt)
	}
}

func (q *memoryQueue) doEnqueue(prio time.Duration, pkt *packet.Packet) {
	// Enqueue the packet unconditionally so that it is a
	// candidate to be dropped.
	q.q.Enqueue(uint64(prio), pkt)

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
