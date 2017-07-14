// priority_queue.go - Priority queue for implementing the Poisson mix strategy.
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
	"encoding/binary"
	"fmt"
	"time"

	"github.com/boltdb/bolt"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("priority_queue")

const (
	SphinxPacketSize = 30000
)

type Item struct {
	sphinx_packet []byte
	priority      uint32
	index         int
}

type PriorityQueue struct {
	queue []*Item
	db    *bolt.DB
}

func New(dbname string) *PriorityQueue {
	pq := PriorityQueue{
		queue: make([]*Item, 0),
	}
	heap.Init(&pq)
	var err error
	pq.db, err = bolt.Open(dbname, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Error(err)
		panic(err)
	}
	return &pq
}

func (pq PriorityQueue) Load() {
	transaction := func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("mix_queue"))
		if bucket == nil {
			log.Error("failed to retrieve mix_queue bucket")
			panic("failed to retrieve mix_queue bucket")
		}
		cursor := bucket.Cursor()
		if cursor == nil {
			log.Error("failed to get bucket cursor")
			panic("failed to get bucket cursor")
		}
		for sphinx_packet, priority := cursor.First(); sphinx_packet != nil; sphinx_packet, priority = cursor.Next() {
			item := Item{
				priority:      binary.BigEndian.Uint32(priority[:4]),
				sphinx_packet: sphinx_packet,
			}
			fmt.Println("Push")
			pq.Push(&item)
			sphinx_packet, priority = cursor.Next()
		}
		return nil
	}

	err := pq.db.View(transaction)
	if err != nil {
		panic(err)
	}
}

func (pq PriorityQueue) Save() error {
	var err error
	transaction := func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("mix_queue"))
		if err != nil {
			log.Errorf("failed to create mix_queue bucket: %s", err)
			panic(err)
		}
		for i := 0; i < len(pq.queue); i++ {
			item := pq.queue[i]
			priorityBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(priorityBytes, item.priority)
			err = bucket.Put(item.sphinx_packet, priorityBytes)
			if err != nil {
				return err
			}
		}
		return nil
	}

	err = pq.db.Update(transaction)
	if err != nil {
		panic(err)
	}
	err = pq.db.Close()
	if err != nil {
		log.Error(err)
	}
	return err
}

func (pq PriorityQueue) Len() int {
	return len(pq.queue)
}

func (pq PriorityQueue) Less(i, j int) bool {
	return pq.queue[i].priority < pq.queue[j].priority
}

func (pq PriorityQueue) Swap(i, j int) {
	pq.queue[i], pq.queue[j] = pq.queue[j], pq.queue[i]
	pq.queue[i].index = i
	pq.queue[j].index = j
}

func (pq *PriorityQueue) Push(x interface{}) {
	n := len(pq.queue)
	item := x.(*Item)
	item.index = n
	pq.queue = append(pq.queue, item)
}

func (pq *PriorityQueue) Pop() interface{} {
	old := pq.queue
	n := len(old)
	item := old[n-1]
	item.index = -1
	pq.queue = old[0 : n-1]
	return item
}

func (pq *PriorityQueue) update(item *Item, sphinx_packet []byte, priority uint32) {
	item.sphinx_packet = sphinx_packet
	item.priority = priority
	heap.Fix(pq, item.index)
}
