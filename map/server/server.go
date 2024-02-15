// server.go - map service using cbor plugin system
// Copyright (C) 2021  Masala
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

package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	bolt "go.etcd.io/bbolt"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/map/crypto"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

const (
	mapBucket = "map"
	gcBucket  = "gc"
)

// Map holds reference to the database and logger and provides methods to store and retrieve data
type Map struct {
	worker.Worker
	log *logging.Logger
	db  *bolt.DB

	mapSize int // number of entries to keep
	gcSize  int // number of entries to place in each garbage bucket
}

// Get retrieves an item from the db
func (m *Map) dbGet(msgID *crypto.MessageID) ([]byte, error) {
	var resp []byte
	err := m.db.View(func(tx *bolt.Tx) error {
		mapBkt := tx.Bucket([]byte(mapBucket))
		if mapBkt == nil {
			return errors.New("mapBucket does not exist")
		}
		p := mapBkt.Get(msgID[:])
		if p == nil {
			// empty slot
			return errors.New("no data")
		}
		resp = make([]byte, len(p))
		copy(resp, p)
		return nil
	})
	return resp, err
}

// Put places an item in the db
func (m *Map) dbPut(msgID *crypto.MessageID, payload []byte) error {
	return m.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(mapBucket))
		p := bkt.Get(msgID[:])
		if p != nil {
			if !bytes.Equal(p, payload) {
				m.log.Errorf("Got different payload for %x", msgID[:])
			}
		}

		err := bkt.Put(msgID[:], payload)
		if err != nil {
			return err
		}

		// get current gc bucket
		bkt = tx.Bucket([]byte(gcBucket))
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], bkt.Sequence())
		gcbkt, err := bkt.CreateBucketIfNotExists(b[:])
		if err != nil {
			return err
		}
		// create new bucket if current bucket is full
		if gcbkt.Stats().KeyN >= m.gcSize {
			i, err := bkt.NextSequence()
			if err != nil {
				return err
			}
			binary.BigEndian.PutUint64(b[:], i)
			gcbkt, err = bkt.CreateBucketIfNotExists(b[:])
			if err != nil {
				return err
			}
		}

		// store msgID in gcBucket
		err = gcbkt.Put(msgID[:], []byte{0x1})
		if err != nil {
			return err
		}

		// use gcBktIdex to get handle to gcBkt
		// if gcBkt is == gcsize increment gcBktIdx, create new bkt, update gcBkt handle
		// store msgID under gcBkt
		return nil
	})
}

// GarbageCollect prunes the oldest bucket of entries when the map size limit is exceeded
func (m *Map) garbageCollect() error {
	return m.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(gcBucket))
		size := bkt.Stats().InlineBucketN * m.gcSize
		if size > m.mapSize {
			// delete map entries in the oldest gcBkt
			k, _ := bkt.Cursor().First()
			gcbkt := bkt.Bucket(k)
			mbkt := tx.Bucket([]byte(mapBucket))
			gcbkt.ForEach(func(k, v []byte) error {
				return mbkt.Delete(k)
			})
			bkt.DeleteBucket(k)
		}
		return nil
	})
}

func (m *Map) Shutdown() {
	m.db.Close()
	m.Halt()
}

func (m *Map) worker() {
	m.log.Notice("Starting garbage collection worker")
	defer m.log.Notice("Stopping garbage collection worker")
	for {
		select {
		case <-m.HaltCh():
			return
		case <-time.After(1 * time.Hour):
			m.garbageCollect()
		}
	}
}

// NewMap instantiates a map
func NewMap(fileStore string, log *logging.Logger, gcSize int, mapSize int) (*Map, error) {
	m := &Map{
		log:     log,
		mapSize: mapSize,
		gcSize:  gcSize,
	}
	db, err := bolt.Open(fileStore, 0600, nil)
	if err != nil {
		log.Errorf("%s", err)
		return nil, err
	}
	m.db = db
	if err = m.db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(mapBucket)); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(gcBucket)); err != nil {
			return err
		}
		return nil
	}); err != nil {
		m.db.Close()
		log.Errorf("%s", err)
		return nil, err
	}
	m.Go(m.worker)
	return m, nil
}

func validate(req *crypto.MapRequest) error {
	switch {
	case req.ReadCap != nil:
		if !req.ReadCap.Verify() {
			return errors.New("failed to verify read capability")
		}
		return nil
	case req.WriteCap != nil:
		if !req.WriteCap.Verify() {
			return errors.New("failed to verify write capability")
		}
		return nil
	case (req.WriteCap != nil) && (req.ReadCap != nil):
		return errors.New("invalid map request, both read and write caps cannot be set")
	case (req.WriteCap == nil) && (req.ReadCap == nil):
		return errors.New("invalid map request, at least one cap must be set")
	default:
		panic("impossible")
	}
	return errors.New("impossible")
}

func (m *Map) OnCommand(cmd cborplugin.Command) (cborplugin.Command, error) {
	switch r := cmd.(type) {
	case *cborplugin.Request:
		if !r.HasSURB {
			return nil, errors.New("no SURB, cannot reply")
		}
		req := &crypto.MapRequest{}
		dec := cbor.NewDecoder(bytes.NewReader(r.Payload))
		err := dec.Decode(req)
		if err != nil {
			return nil, err
		}

		// validate the capabilities of MapRequest
		err = validate(req)
		if err != nil {
			m.log.Errorf("verification failed: %s", err)
			return nil, fmt.Errorf("verification failed: %s", err)
		}

		resp := &crypto.MapResponse{}
		// Write data if payload present
		if req.WriteCap != nil {
			err := m.dbPut(req.WriteCap.ID, req.WriteCap.Payload)
			if err != nil {
				m.log.Debugf("Put(%x): Failed", req.WriteCap.ID)
				resp.Status = crypto.StatusFailed
			} else {
				m.log.Debugf("Put(%x): OK", req.WriteCap.ID)
				resp.Status = crypto.StatusOK
			}
			// Otherwise request data
		} else {
			p, err := m.dbGet(req.ReadCap.ID)
			if err != nil {
				m.log.Debugf("Get(%x): NotFound", req.ReadCap.ID)
				resp.Status = crypto.StatusNotFound
			} else {
				m.log.Debugf("Get(%x): OK", req.ReadCap.ID)
				resp.Status = crypto.StatusOK
				resp.Payload = p
			}
		}
		rawResp, err := resp.Marshal()
		if err != nil {
			return nil, err
		}
		return &cborplugin.Response{Payload: rawResp}, nil
	default:
		m.log.Errorf("OnCommand called with unknown Command type")
		return nil, errors.New("invalid Command type")
	}
}

// RegisterConsumer is a no-op but necessary for this type to satisfy
// the cborplugin.ServerPlugin interface.
func (m *Map) RegisterConsumer(svr *cborplugin.Server) {
	m.log.Debugf("RegisterConsumer called")
}
