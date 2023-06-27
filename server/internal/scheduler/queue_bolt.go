// queue_bolt.go - Katzenpost scheduler BoltDB queue.
// Copyright (C) 2018  Yawning Angel.
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
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/instrument"
	"github.com/katzenpost/katzenpost/server/internal/packet"
	bolt "go.etcd.io/bbolt"
	"gopkg.in/op/go-logging.v1"
)

const (
	boltQueuePath = "external_queue.db"

	boltPacketKeySize   = 8 + 8
	boltPacketTimesSize = 8 + 8 + 8

	boltPacketsBucket        = "packets"
	boltPacketRawKey         = "raw"
	boltPacketPayloadKey     = "payload"
	boltPacketCommandsKey    = "commands"
	boltPacketTimesKey       = "times"
	boltPacketMustForwardKey = "mustForward"
)

var (
	errNotForward     = errors.New("packet is not forward")
	errMustTerminate  = errors.New("packet has MustTerminate set")
	errMalformedTimes = errors.New("packet has malformed timestamp vector")

	boltPacketMustForward = []byte{0x01}
)

func packetToBoltBkt(parentBkt *bolt.Bucket, pkt *packet.Packet, prio time.Time) error {
	// Since the packet is entering the mix queue, by definition, it is
	// a forward packet.  Ensure this invariant is true.
	if !pkt.IsForward() {
		return errNotForward
	}
	if pkt.MustTerminate {
		return errMustTerminate
	}

	// Use `prio || pkt.ID` as the key so that it is possible to handle
	// the extremely unlikely case of priority collisions.
	//
	// Yes, there's some suboptimal behavior due to pkt.ID monotonically
	// increasing, but it's something that "should never happen" in the
	// first place.
	var pktKey [boltPacketKeySize]byte
	binary.BigEndian.PutUint64(pktKey[0:], uint64(prio.UnixNano()))
	binary.BigEndian.PutUint64(pktKey[8:], pkt.ID)
	bkt, err := parentBkt.CreateBucket(pktKey[:])
	if err != nil {
		return err
	}
	rawBuf := make([]byte, 0, len(pkt.Raw))
	rawBuf = append(rawBuf, pkt.Raw...)
	err = bkt.Put([]byte(boltPacketRawKey), rawBuf)
	if err != nil {
		return err
	}
	if pkt.Payload != nil {
		payloadBuf := make([]byte, 0, len(pkt.Payload))
		payloadBuf = append(payloadBuf, pkt.Payload...)
		err = bkt.Put([]byte(boltPacketPayloadKey), payloadBuf)
		if err != nil {
			return err
		}
	}

	boltPacketCommandsSize := pkt.Geometry.NextNodeHopLength

	cmdBuf := make([]byte, 0, boltPacketCommandsSize)
	cmdBuf = pkt.NextNodeHop.ToBytes(cmdBuf)
	cmdBuf = pkt.NodeDelay.ToBytes(cmdBuf)
	err = bkt.Put([]byte(boltPacketCommandsKey), cmdBuf)
	if err != nil {
		return err
	}

	var timesBuf [boltPacketTimesSize]byte
	binary.BigEndian.PutUint64(timesBuf[0:], uint64(pkt.Delay))
	binary.BigEndian.PutUint64(timesBuf[8:], uint64(pkt.RecvAt.UnixNano()))
	binary.BigEndian.PutUint64(timesBuf[16:], uint64(pkt.DispatchAt.UnixNano()))
	err = bkt.Put([]byte(boltPacketTimesKey), timesBuf[:])
	if err != nil {
		return err
	}

	// Pointless, this flag isn't examined past the crypto worker,
	// because it's sole purpose is to prevent a client from sending
	// to a local user, but save it anyway.
	if pkt.MustForward {
		err = bkt.Put([]byte(boltPacketMustForwardKey), boltPacketMustForward)
	}

	return err
}

func packetFromBoltBkt(parentBkt *bolt.Bucket, k []byte, g glue.Glue) (*packet.Packet, error) {
	bkt := parentBkt.Bucket(k)
	if bkt == nil {
		panic("BUG: packet does not exist")
	}
	pkt, err := packet.NewWithID(
		bkt.Get([]byte(boltPacketRawKey)),
		binary.BigEndian.Uint64(k[8:]),
		g.Config().SphinxGeometry,
	)
	if err != nil {
		return nil, err
	}
	var payload []byte
	if b := bkt.Get([]byte(boltPacketPayloadKey)); b != nil {
		payload = make([]byte, 0, len(b))
		payload = append(payload, b...)
	}

	cmds := make([]commands.RoutingCommand, 0, 2)
	cmdBuf := bkt.Get([]byte(boltPacketCommandsKey))
	for {
		cmd, rest, err := commands.FromBytes(cmdBuf, g.Config().SphinxGeometry)
		if err != nil {
			pkt.Dispose()
			return nil, err
		}
		if cmd == nil {
			if rest != nil {
				panic("BUG: serialized commands has trailing garbage")
			}
			break
		}

		cmds = append(cmds, cmd)
		cmdBuf = rest
	}
	if err = pkt.Set(payload, cmds); err != nil {
		pkt.Dispose()
		return nil, err
	}

	if b := bkt.Get([]byte(boltPacketTimesKey)); len(b) == boltPacketTimesSize {
		pkt.Delay = time.Duration(binary.BigEndian.Uint64(b[0:]))
		pkt.RecvAt = time.Unix(0, int64(binary.BigEndian.Uint64(b[8:])))
		pkt.DispatchAt = time.Unix(0, int64(binary.BigEndian.Uint64(b[16:])))
	} else {
		pkt.Dispose()
		return nil, errMalformedTimes
	}

	if b := bkt.Get([]byte(boltPacketMustForwardKey)); b != nil {
		pkt.MustForward = true
	}

	// Cheap sanity check.
	if !pkt.IsForward() {
		pkt.Dispose()
		return nil, errNotForward
	}

	return pkt, nil
}

type boltQueue struct {
	glue glue.Glue
	log  *logging.Logger

	db *bolt.DB

	headPkt  *packet.Packet
	headPrio time.Time

	dbCount uint64
}

func (q *boltQueue) Halt() {
	if q.db != nil {
		f := q.db.Path()
		q.db.Close()
		os.Remove(f)
		q.db = nil
	}
}

func (q *boltQueue) Peek() (time.Time, *packet.Packet) {
	return q.headPrio, q.headPkt
}

func (q *boltQueue) Pop() {
	if q.headPkt != nil {
		q.headPkt = nil
		q.headPrio = time.Time{}
		if q.dbCount == 0 {
			return
		}
	} else {
		panic("BUG: Pop() called on empty queue")
	}

	now := time.Now()
	timerSlack := time.Duration(q.glue.Config().Debug.SchedulerSlack) * time.Millisecond

	var removed uint64
	err := q.db.Update(func(tx *bolt.Tx) error {
		packetsBkt := tx.Bucket([]byte(boltPacketsBucket))

		cur := packetsBkt.Cursor()
		for k, v := cur.First(); k != nil; k, v = cur.Next() {
			if v != nil {
				continue
			}
			if len(k) != boltPacketKeySize {
				panic("BUG: serialized packet has invalid key")
			}

			// Figure out if the packet's deadline is blown.  This replicates
			// some code from scheduler.worker(), but dropping en-mass in a
			// single transactions is the sensible thing to do.
			prio := time.Unix(0, int64(binary.BigEndian.Uint64(k[0:])))
			id := binary.BigEndian.Uint64(k[8:])
			var pkt *packet.Packet
			var err error
			if deltaT := now.Sub(prio); deltaT > timerSlack {
				q.log.Debugf("Dropping packet: %v (Deadline blown by %v)", id, deltaT)
				instrument.DeadlineBlownPacketsDropped()
				instrument.OutgoingPacketsDropped()
				instrument.PacketsDropped()
			} else if pkt, err = packetFromBoltBkt(packetsBkt, k, q.glue); err != nil {
				q.log.Debugf("Dropping packet: %v (s11n failure: %v)", id, err)
				instrument.InvalidPacketsDropped()
				instrument.OutgoingPacketsDropped()
				instrument.PacketsDropped()
			}

			// Regardless of what happened, obliterate the bucket.
			err = packetsBkt.DeleteBucket(k)
			if err != nil {
				return err
			}

			removed++

			if pkt != nil {
				q.headPkt = pkt
				q.headPrio = prio
				return nil
			}
		}

		return nil
	})
	if err != nil {
		q.log.Errorf("Pop(): Transaction failed: %v", err)
		panic("Pop() failed.")
	} else {
		q.dbCount -= removed
		q.log.Debugf("Pop(): Count %v (Removed %v, Elapsed: %v).", q.dbCount, removed, time.Now().Sub(now))
	}
}

func (q *boltQueue) BulkEnqueue(batch []*packet.Packet) {
	var added uint64
	now := time.Now()

	// Special case enqueuing a single packet, with a totally empty queue.
	if len(batch) == 1 && q.dbCount == 0 && q.headPkt == nil {
		q.log.Debugf("BulkEnqueue(): Taking fast path.")
		q.headPkt = batch[0]
		q.headPrio = now.Add(batch[0].Delay)
		return
	}

	err := q.db.Update(func(tx *bolt.Tx) error {
		packetsBkt := tx.Bucket([]byte(boltPacketsBucket))
		for _, pkt := range batch {
			prio := now.Add(pkt.Delay)

			if q.headPkt == nil {
				q.headPkt = pkt
				q.headPrio = prio
				continue
			}
			if q.headPrio.After(prio) {
				pkt, q.headPkt = q.headPkt, pkt
				prio, q.headPrio = q.headPrio, prio
			}

			if err := packetToBoltBkt(packetsBkt, pkt, prio); err != nil {
				q.log.Warningf("Failed to enqueue packet: %v (%v)", pkt.ID, err)
				instrument.OutgoingPacketsDropped()
				instrument.PacketsDropped()
			} else {
				added++
			}
			pkt.Dispose()
		}

		return nil
	})
	if err != nil {
		q.log.Errorf("BulkEnqueue(): Transaction failed: %v", err)
	} else {
		q.dbCount += added
		q.log.Debugf("BulkEnqueue(): Count %v (Added %v, Elapsed: %v).", q.dbCount, added, time.Now().Sub(now))
	}
}

func newBoltQueue(glue glue.Glue) (queueImpl, error) {
	q := &boltQueue{
		glue: glue,
		log:  glue.LogBackend().GetLogger("scheduler/bolt"),
	}

	f := filepath.Join(glue.Config().Server.DataDir, boltQueuePath)
	if _, err := os.Lstat(f); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("scheduler/bolt: Failed to stat() db: %v", err)
		}
	} else if err = os.Remove(f); err != nil {
		return nil, fmt.Errorf("scheduler/bolt: Failed to remove old db: %v", err)
	}

	var err error
	dbOptions := &bolt.Options{
		// The documentation has dire warnings about setting this, because
		// write reordering can leave the database in a trashed state on a
		// crash.  But we explicitly re-create the db on each startup.
		NoSync:         true,
		NoFreelistSync: true,
	}
	q.db, err = bolt.Open(f, 0600, dbOptions)
	if err != nil {
		return nil, err
	}
	if err = q.db.Update(func(tx *bolt.Tx) error {
		_, err = tx.CreateBucketIfNotExists([]byte(boltPacketsBucket))
		return err
	}); err != nil {
		q.Halt()
		return nil, err
	}

	return q, nil
}
