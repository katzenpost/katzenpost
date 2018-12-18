// priority_queue_test.go - Tests for priority queue.
// Copyright (C) 2017, 2018  David Anthony Stainton, Yawning Angel
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

package queue

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPriorityQueue(t *testing.T) {
	require := require.New(t)

	testEntries := []Entry{
		{
			Value:    []byte("That books do not take the place of experience,"),
			Priority: 0,
		},

		{
			Value:    []byte("and that learning is no substitute for genius,"),
			Priority: 1,
		},
		{
			Value:    []byte("are two kindred phenomena;"),
			Priority: 2,
		},
		{
			Value:    []byte("their common ground is that the abstract can never take the place of the perceptive."),
			Priority: 3,
		},
		{
			Value:    []byte(" -- Arthur_Schopenhauer"),
			Priority: 4,
		},
	}

	q := New()
	for _, v := range testEntries {
		q.Enqueue(v.Priority, v.Value)
	}
	require.Equal(len(testEntries), q.Len(), "Queue length (full)")

	for i, expected := range testEntries {
		require.Equal(len(testEntries)-i, q.Len(), "Queue length")

		// Peek
		ent := q.Peek()
		require.Equal(expected.Value, ent.Value, "Peek(): Value")
		require.Equal(expected.Priority, ent.Priority, "Peek(): Priority")

		// Pop
		ent = q.Pop()
		require.Equal(expected.Value, ent.Value, "Pop(): Value")
		require.Equal(expected.Priority, ent.Priority, "Pop(): Priority")

		s := ent.Value.([]byte)
		t.Logf("ent[%d]: %d %s", i, ent.Priority, s)
	}

	require.Equal(0, q.Len(), "Queue length (empty)")
	require.Nil(q.Peek(), "Peek() (empty)")
	require.Nil(q.Pop(), "Pop() (empty)")

	// Refill the queue.
	for _, v := range testEntries {
		q.Enqueue(v.Priority, v.Value)
	}
	require.Equal(len(testEntries), q.Len(), "Queue length (full), pre-rand test")

	r := rand.New(rand.NewSource(23)) // Don't do this in production.
	for i := 0; i < len(testEntries); i++ {
		ent := q.DequeueRandom(r)
		s := ent.Value.([]byte)
		t.Logf("random ent[%d]: %d %s", i, ent.Priority, s)
	}
	require.Equal(0, q.Len(), "Queue length (empty), post-rand test")
}

func TestFilterOnce(t *testing.T) {
	require := require.New(t)

	testEntries := []Entry{
		{
			Value:    []byte("But as academics gravitated to cryptography, they tended to sanitize it, stripping it of ostensible connectedness to power."),
			Priority: 0,
		},

		{
			Value:    []byte("Applied and privacy-related work drifted outside of the field’s core venues, the IACR conferences."),
			Priority: 1,
		},
		{
			Value:    []byte("It is as though a chemical synthesis would take place, transforming this powerful powder into harmless dust."),
			Priority: 2,
		},
	}

	q := New()
	for _, v := range testEntries {
		q.Enqueue(v.Priority, v.Value)
	}
	require.Equal(len(testEntries), q.Len(), "Queue length (full)")

	filter := func(value interface{}) bool {
		str := value.([]byte)
		return strings.Contains(string(str), "academics")
	}

	s := string(q.Peek().Value.([]byte))
	require.True(strings.Contains(s, "academics"))
	q.FilterOnce(filter)
	s = string(q.Peek().Value.([]byte))
	require.False(strings.Contains(s, "academics"))
}
