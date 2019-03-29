// timerq_test.go - Time delayed queue tests
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

package session

import (
	"io"
	"testing"
	"time"

	"github.com/katzenpost/core/crypto/rand"
	"github.com/stretchr/testify/assert"
)

func TestNewTimerQ(t *testing.T) {
	// create a Queue for rescheduled messages
	q := new(Queue)

	a := NewTimerQ(q)
	a.Halt()
}

func TestTimerQPush(t *testing.T) {
	assert := assert.New(t)

	// create a queue for rescheduled messages
	q := new(Queue)

	a := NewTimerQ(q)

	// enqueue 10 messages
	for i := 0; i < 10; i++ {
		m := &Message{}
		m.ID = new([16]byte)

		m.SentAt = time.Now()
		m.ReplyETA = 200 * time.Millisecond
		io.ReadFull(rand.Reader, m.ID[:])

		prio := uint64(m.SentAt.Add(m.ReplyETA).UnixNano())
		a.Push(prio, m)
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

func TestTimerQRemove(t *testing.T) {
	assert := assert.New(t)

	// create a Queue for forwarded messages
	q := new(Queue)

	a := NewTimerQ(q)

	// enqueue 10 messages, and call TimerQ.Remove() on half of them before their timers expire
	for i := 0; i < 10; i++ {
		m := &Message{}
		m.ID = new([16]byte)

		m.SentAt = time.Now()
		m.ReplyETA = 100 * time.Millisecond
		io.ReadFull(rand.Reader, m.ID[:])
		prio := uint64(m.SentAt.Add(m.ReplyETA).UnixNano())
		a.Push(prio, m)
		<-time.After(20 * time.Millisecond)
		if i%2 == 0 {
			er := a.Remove(m)
			assert.NoError(er)
		}
		<-time.After(80 * time.Millisecond)
	}
	t.Logf("Sent 10 messages")
	<-time.After(3 * time.Second)

	j := 0
	for {
		_, err := q.Pop()
		if err == ErrQueueEmpty {
			break
		}
		j++
	}
	t.Logf("Popped %d messages", j)

	// verify that half of the messages were sent to q
	assert.Equal(5, j)
	a.Halt()
}
