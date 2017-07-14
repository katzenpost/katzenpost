// priority_queue_test.go - Tests for priority queue.
// This was inspired by the priority queue example in the godocs:
// https://golang.org/pkg/container/heap/
// Copyright (C) 2017  David Anthony Stainton
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
	"container/heap"
	//"github.com/stretchr/testify/require"
	"testing"
)

func TestPriorityQueue(t *testing.T) {
	//require := require.New(t)

	q := New("test_db.0")
	heap.Init(q)
	i := Item{
		sphinx_packet: []byte("test string 123"),
		priority:      10,
	}
	heap.Push(q, &i)
	q.Save()

	q = New("test_db.0")
	heap.Init(q)
	q.Load()
	_ = heap.Pop(q)
	//require.Equal(item.sphinx_packet, i.sphinx_packet)
	//	require.Equal(item.priority, i.priority)
}
