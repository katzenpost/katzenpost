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
	"errors"
	"github.com/fxamacker/cbor/v2"
	bolt "go.etcd.io/bbolt"
	"gopkg.in/op/go-logging.v1"
	"time"

	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/map/common"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

const (
	mapBucket = "map"
)

// Map holds reference to the database and logger and provides methods to store and retrieve data
type Map struct {
	worker.Worker
	log *logging.Logger
	db  *bolt.DB
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
			return errors.New("no data")
		}
		resp = make([]byte, len(p))
		copy(resp, p)
		return nil
	})
	return resp, err
}

// Put places an item in the db
func (m *Map) Put(msgID common.MessageID, payload []byte) error {
	return m.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(mapBucket))
		err := bkt.Put(msgID[:], payload)
		if err != nil {
			return err
		}
		return nil
	})
}

// GarbageCollect prunes items older than time
// XXX: timestamps must not be granular than an epoch period (weekly or key rotation - which?)
func (m *Map) GarbageCollect(before time.Time) error {
	return nil
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
			m.GarbageCollect(time.Now().Add(-24 * time.Hour))
		}
	}
}

// NewMap instantiates a map
func NewMap(fileStore string, log *logging.Logger) (*Map, error) {
	m := &Map{
		log: log,
	}
	db, err := bolt.Open(fileStore, 0600, nil)
	if err != nil {
		log.Errorf("%s", err)
		panic(err)
		return nil, err
	}
	m.db = db
	if err = m.db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(mapBucket)); err != nil {
			return err
		}
		return nil
	}); err != nil {
		m.db.Close()
		log.Errorf("%s", err)
		panic(err)
		return nil, err
	}
	m.Go(m.worker)
	return m, nil
}

func (m *Map) OnCommand(cmd cborplugin.Command) (cborplugin.Command, error) {
	switch r := cmd.(type) {
	case *cborplugin.Request:
		if !r.HasSURB {
			return nil, errors.New("No SURB, cannot reply")
		}
		req := &common.MapRequest{}
		dec := cbor.NewDecoder(bytes.NewReader(r.Payload))
		err := dec.Decode(req)
		if err != nil {
			return nil, err
		}

		resp := &common.MapResponse{}
		// Write data if payload present
		if len(req.Payload) > 0 {
			err := m.Put(req.TID, req.Payload)
			if err != nil {
				resp.Status = common.StatusFailed
			} else {
				resp.Status = common.StatusOK
			}
			// Otherwise request data
		} else {
			p, err := m.Get(req.TID)
			if err != nil {
				resp.Status = common.StatusNotFound
			} else {
				resp.Status = common.StatusOK
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
		return nil, errors.New("Invalid Command type")
	}
}

func (m *Map) RegisterConsumer(svr *cborplugin.Server) {
	m.log.Debugf("RegisterConsumer called")
}
