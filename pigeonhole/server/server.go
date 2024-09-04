// server.go - pigeonhole service using cbor plugin system
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
	"github.com/katzenpost/katzenpost/pigeonhole/common"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

const (
	pigeonHoleBucket = "pigeonHole"
	gcBucket         = "gc"
)

// PigeonHole holds reference to the database and logger and provides methods to store and retrieve data
type PigeonHole struct {
	worker.Worker
	log *logging.Logger
	db  *bolt.DB

	pigeonHoleSize int // number of entries to keep
	gcSize         int // number of entries to place in each garbage bucket

	waiting map[common.MessageID][]*cborplugin.Response
	write   func(cborplugin.Command)
}

// Wait adds pending cborplugin.Responses (with SURBs) by MessageID to a waiting map
func (m *PigeonHole) Wait(msgID common.MessageID, response *cborplugin.Response) {
	_, ok := m.waiting[msgID]
	if !ok {
		m.waiting[msgID] = []*cborplugin.Response{response}
	} else {
		m.waiting[msgID] = append(m.waiting[msgID], response)
	}
}

// Wake returns the pending responses from the waiting map and removes the entries
func (m *PigeonHole) Wake(msgID common.MessageID) []*cborplugin.Response {
	w, ok := m.waiting[msgID]
	if !ok {
		return []*cborplugin.Response{}
	}
	delete(m.waiting, msgID)
	return w
}

// Get retrieves an item from the db
func (m *PigeonHole) Get(msgID common.MessageID) ([]byte, error) {
	var resp []byte
	err := m.db.View(func(tx *bolt.Tx) error {
		pigeonHoleBkt := tx.Bucket([]byte(pigeonHoleBucket))
		if pigeonHoleBkt == nil {
			return errors.New("pigeonHoleBucket does not exist")
		}
		p := pigeonHoleBkt.Get(msgID[:])
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
func (m *PigeonHole) Put(msgID common.MessageID, payload []byte) error {
	err := m.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(pigeonHoleBucket))
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
	if err != nil {
		return err
	}

	// respond to any Get's that were waiting for this Put
	pigeonHoleResponse := &common.PigeonHoleResponse{Status: common.StatusOK, Payload: payload}
	rawResp, err := pigeonHoleResponse.Marshal()
	if err != nil {
		return nil
	}

	for _, pluginResponse := range m.Wake(msgID) {
		pluginResponse.Payload = rawResp
		m.write(pluginResponse)
	}
	return nil
}

// GarbageCollect prunes the oldest bucket of entries when the pigeonHole size limit is exceeded
func (m *PigeonHole) GarbageCollect() error {
	return m.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(gcBucket))
		size := bkt.Stats().InlineBucketN * m.gcSize
		if size > m.pigeonHoleSize {
			// delete pigeonHole entries in the oldest gcBkt
			k, _ := bkt.Cursor().First()
			gcbkt := bkt.Bucket(k)
			mbkt := tx.Bucket([]byte(pigeonHoleBucket))
			gcbkt.ForEach(func(k, v []byte) error {
				return mbkt.Delete(k)
			})
			bkt.DeleteBucket(k)
		}
		return nil
	})
}

func (m *PigeonHole) Shutdown() {
	m.db.Close()
	m.Halt()
}

func (m *PigeonHole) worker() {
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

// NewPigeonHole instantiates a pigeonHole
func NewPigeonHole(fileStore string, log *logging.Logger, gcSize int, pigeonHoleSize int) (*PigeonHole, error) {
	m := &PigeonHole{
		log:            log,
		pigeonHoleSize: pigeonHoleSize,
		gcSize:         gcSize,
		waiting:        make(map[common.MessageID][]*cborplugin.Response),
	}
	db, err := bolt.Open(fileStore, 0600, nil)
	if err != nil {
		log.Errorf("%s", err)
		return nil, err
	}
	m.db = db
	if err = m.db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(pigeonHoleBucket)); err != nil {
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

func (m *PigeonHole) OnCommand(cmd cborplugin.Command) error {
	switch r := cmd.(type) {
	case *cborplugin.Request:
		if r.SURB == nil {
			return errors.New("no SURB, cannot reply")
		}
		req := &common.PigeonHoleRequest{}
		dec := cbor.NewDecoder(bytes.NewReader(r.Payload))
		err := dec.Decode(req)
		if err != nil {
			return err
		}

		// validate the capabilities of PigeonHoleRequest
		if !validateCap(req) {
			m.log.Errorf("validateCap failed with error %s", err)
			return errors.New("failed to verify capability")
		}

		resp := &common.PigeonHoleResponse{}
		// Write data if payload present
		if len(req.Payload) > 0 {
			err := m.Put(req.ID, req.Payload)
			if err != nil {
				m.log.Debugf("Put(%x): Failed", req.ID)
				resp.Status = common.StatusFailed
			} else {
				m.log.Debugf("Put(%x): OK", req.ID)
				resp.Status = common.StatusOK
			}
			waiting := m.Wake(req.ID)
			for _, pluginResponse := range waiting {
				pigeonHoleResponse := &common.PigeonHoleResponse{Status: common.StatusOK, Payload: req.Payload}
				rawResp, err := pigeonHoleResponse.Marshal()
				if err != nil {
					return nil
				}
				pluginResponse.Payload = rawResp
				m.write(pluginResponse)
			}
			// Otherwise request data
		} else {
			p, err := m.Get(req.ID)
			if err != nil {
				m.log.Debugf("Get(%x): Wait", req.ID)
				m.Wait(req.ID, &cborplugin.Response{ID: r.ID, SURB: r.SURB})
				return nil
			} else {
				m.log.Debugf("Get(%x): OK", req.ID)
				resp.Status = common.StatusOK
				resp.Payload = p
			}
		}
		rawResp, err := resp.Marshal()
		if err != nil {
			return err
		}
		m.write(&cborplugin.Response{ID: r.ID, SURB: r.SURB, Payload: rawResp})
		return nil
	default:
		m.log.Errorf("OnCommand called with unknown Command type")
		return errors.New("invalid Command type")
	}
}

func validateCap(req *common.PigeonHoleRequest) bool {
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

func (m *PigeonHole) RegisterConsumer(svr *cborplugin.Server) {
	m.write = svr.Write
}
