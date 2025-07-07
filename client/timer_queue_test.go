//go:build !darwin && !windows
// +build !darwin,!windows

// timer_queue_test.go - Time delayed queue tests
// Copyright (C) 2018  Masala, David Stainton.
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
	"io"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/katzenpost/hpqc/rand"
	"github.com/stretchr/testify/assert"
)

func TestNewTimerQueue(t *testing.T) {
	t.Parallel()
	// create a Queue for rescheduled messages
	q := new(Queue)

	a := NewTimerQueue(q)
	a.Go(a.worker)
	a.Halt()
}

func TestTimerQueuePush(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	// create a queue for rescheduled messages
	q := new(Queue)

	a := NewTimerQueue(q)
	a.Go(a.worker)

	// enqueue 10 messages
	for i := 0; i < 10; i++ {
		m := &Message{}
		m.ID = new([16]byte)

		m.SentAt = time.Now()
		m.ReplyETA = 200 * time.Millisecond
		_, err := io.ReadFull(rand.Reader, m.ID[:])
		assert.NoError(err)

		a.Push(m)
		<-time.After(1 * time.Millisecond)
	}
	t.Logf("Sent 10 messages")

	// wait for all of the timers to expire and each message to be enqueued in q
	<-time.After(1 * time.Second)

	j := 0
	for {
		_, err := q.Pop()
		if err == ErrQueueEmpty {
			break
		}
		j++
	}
	t.Logf("Pop() %d messages", j)

	// Verify that all messages were placed into q
	assert.Equal(10, j)
	a.Halt()
}

func TestTimerQueueOrder(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	// create a Queue for forwarded messages
	q := new(Queue)

	a := NewTimerQueue(q)
	a.Go(a.worker)

	r := mrand.New(mrand.NewSource(0))

	for i := 0; i < 10; i++ {
		m := &Message{}
		m.ID = new([16]byte)
		m.SentAt = time.Now()
		m.ReplyETA = time.Duration(int(time.Millisecond) * r.Intn(100))
		m.SetPriority(uint64((m.SentAt.Add(m.ReplyETA)).UnixNano()))
		m.ID[0] = uint8(i)
		t.Logf("Inserting: %x : %d", m.ID[0], m.Priority())
		a.Push(m)
	}

	t.Logf("\n")
	<-time.After(1 * time.Second)
	j := 0
	var last uint64
	last = 0xEFFFFFFF
	for {
		n, err := q.Pop()
		if err == ErrQueueEmpty {
			break
		}
		t.Logf("Popping:   %x : %d", n.(*Message).ID[0], n.(*Message).Priority())
		assert.True(n.(*Message).Priority() > last)
		last = n.(*Message).Priority()
		j++
	}
	t.Logf("Popped %d messages", j)
	a.Halt()
}
