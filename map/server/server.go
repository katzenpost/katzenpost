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
	"time"

	"github.com/fxamacker/cbor/v2"
	bolt "go.etcd.io/bbolt"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/map/common"
	"github.com/katzenpost/katzenpost/server/cborplugin"

	"sync"
)

const (
	mapBucket = "map"
	gcBucket  = "gc"
)

// Map holds reference to the database and logger and provides methods to store and retrieve data
type Map struct {
	worker.Worker
	l   *sync.Mutex
	log *logging.Logger
	db  *bolt.DB

	mapSize int // number of entries to keep
	gcSize  int // number of entries to place in each garbage bucket

	waiting map[common.MessageID][]*cborplugin.Response
	write   func(cborplugin.Command)
}

// Wait adds pending cborplugin.Responses (with SURBs) by MessageID to a waiting map
func (m *Map) Wait(msgID common.MessageID, response *cborplugin.Response) {
	m.l.Lock()
	defer m.l.Unlock()
	_, ok := m.waiting[msgID]
	if !ok {
		m.waiting[msgID] = []*cborplugin.Response{response}
	} else {
		m.waiting[msgID] = append(m.waiting[msgID], response)
	}
}

// Wake returns the pending responses from the waiting map and removes the entries
func (m *Map) Wake(msgID common.MessageID, payload []byte) error {
	m.l.Lock()
	defer m.l.Unlock()
	waiting, ok := m.waiting[msgID]
	if !ok {
		return nil // nothing waiting is not an error
	}
	delete(m.waiting, msgID)
	m.log.Debugf("Woke %d: %x", len(waiting), msgID)

	// prepare the response payload for pending requests
	mapResponse := &common.MapResponse{Status: common.StatusOK, Payload: payload}
	rawResp, err := mapResponse.Marshal()
	if err != nil {
		m.log.Errorf("Wake(%x): %v", msgID, err)
		return err
	}

	// respond to any Get's that were waiting for this Put from another routine
	m.Go(func() {
		for _, pluginResponse := range waiting {
			// verify that the pluginResponse SURB and ID fields are intact
			pluginResponse.Payload = rawResp
			m.write(pluginResponse)
			m.log.Debugf("sent pluginResponse for %x", msgID)
		}
	})
	return nil
}

// Get retrieves an item from the db
func (m *Map) Get(msgID common.MessageID) ([]byte, error) {
	var resp []byte
	err := m.db.View(func(tx *bolt.Tx) error {
		mapBkt := tx.Bucket([]byte(mapBucket))
		if mapBkt == nil {
			return errors.New("mapBucket does not exist")
		}
		p := mapBkt.Get(msgID[:])
		if p == nil {
			// empty slot
			return common.ErrStatusNotFound
		}
		resp = make([]byte, len(p))
		copy(resp, p)
		return nil
	})
	return resp, err
}

// Put places an item in the db
func (m *Map) Put(msgID common.MessageID, payload []byte) error {
	err := m.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(mapBucket))
		p := bkt.Get(msgID[:])
		if p != nil {
			if !bytes.Equal(p, payload) {
				m.log.Errorf("Got different payload for %x", msgID[:])
			}
		}

		// store message in mapBucket
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
	if err != nil {
		return err
	}

	return nil
}

// GarbageCollect prunes the oldest bucket of entries when the map size limit is exceeded
func (m *Map) GarbageCollect() error {
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
			m.GarbageCollect()
		}
	}
}

// NewMap instantiates a map
func NewMap(fileStore string, log *logging.Logger, gcSize int, mapSize int) (*Map, error) {
	m := &Map{
		l:       new(sync.Mutex),
		log:     log,
		mapSize: mapSize,
		gcSize:  gcSize,
		waiting: make(map[common.MessageID][]*cborplugin.Response),
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

func (m *Map) OnCommand(cmd cborplugin.Command) error {
	switch r := cmd.(type) {
	case *cborplugin.Request:
		if r.SURB == nil {
			return errors.New("no SURB, cannot reply")
		}
		req := &common.MapRequest{}
		dec := cbor.NewDecoder(bytes.NewReader(r.Payload))
		err := dec.Decode(req)
		if err != nil {
			return err
		}

		resp := &common.MapResponse{}
		// validate the capabilities of MapRequest
		if !validateCap(req) {
			resp.Status = common.StatusFailed
			m.log.Errorf("validateCap failed for %x", req.ID)
		} else {
			// Write data if payload present
			if len(req.Payload) > 0 {
				m.log.Debugf("Put(%x)", req.ID)

				// save payload
				err := m.Put(req.ID, req.Payload)
				if err != nil {
					m.log.Debugf("Put(%x): Failed", req.ID)
					resp.Status = common.StatusFailed
				} else {
					m.log.Debugf("Put(%x): OK", req.ID)
					resp.Status = common.StatusOK
				}

				// Wake pending Get requests and respond with payload
				err = m.Wake(req.ID, req.Payload)
				if err != nil {
					m.log.Errorf("Wake(%x): %v", req.ID, err)
				}

				// Otherwise request data
			} else {
				p, err := m.Get(req.ID)
				if err != nil {
					m.log.Debugf("m.Get(%x): %v", req.ID, err)
					// wait for future data
					m.Wait(req.ID, &cborplugin.Response{ID: r.ID, SURB: r.SURB})
					// do not use SURB, return nil
					return nil
				} else {
					// data was found, respond immediately
					m.log.Debugf("Get(%x): OK", req.ID)
					resp.Status = common.StatusOK
					resp.Payload = p
				}
			}
		}
		// marshal response to this request
		rawResp, err := resp.Marshal()
		if err != nil {
			m.log.Errorf("failure to marshal!?: %v", err)
			return err
		}
		m.write(&cborplugin.Response{ID: r.ID, SURB: r.SURB, Payload: rawResp})
		m.log.Debugf("Sent response to command for %x", req.ID)
		return nil
	default:
		m.log.Errorf("OnCommand called with unknown Command type")
		return errors.New("invalid Command type")
	}
}

func validateCap(req *common.MapRequest) bool {
	if len(req.Payload) == 0 {
		v := req.ID.ReadVerifier()
		// verify v Signs the publickey bytes
		return v.Verify(req.Signature, req.ID.Bytes())
	} else {
		v := req.ID.WriteVerifier()
		// verify v Signs the payload bytes
		return v.Verify(req.Signature, req.Payload)
	}
}

func (m *Map) RegisterConsumer(svr *cborplugin.Server) {
	m.write = svr.Write
}
