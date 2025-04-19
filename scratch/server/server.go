// server.go - scratch service using cbor plugin system
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

	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/scratch/common"
	"github.com/katzenpost/katzenpost/server/cborplugin"

	"sync"
)

const (
	scratchBucket = "scratch"
	gcBucket         = "gc"
)

// Scratch holds reference to the database and logger and provides methods to store and retrieve data
type Scratch struct {
	worker.Worker
	l   *sync.Mutex
	log *logging.Logger
	db  *bolt.DB

	scratchSize int // number of entries to keep
	gcSize         int // number of entries to place in each garbage bucket

	waiting map[[ed25519.PublicKeySize]byte][]*cborplugin.Response
	write   func(cborplugin.Command)
}

// Wait adds pending cborplugin.Responses (with SURBs) by MessageID to a waiting map
func (m *Scratch) Wait(msgID *[ed25519.PublicKeySize]byte, response *cborplugin.Response) {
	m.l.Lock()
	defer m.l.Unlock()
	_, ok := m.waiting[*msgID]
	if !ok {
		m.waiting[*msgID] = []*cborplugin.Response{response}
	} else {
		m.waiting[*msgID] = append(m.waiting[*msgID], response)
	}
}

// Wake returns the pending responses from the waiting map and removes the entries
func (m *Scratch) Wake(msgID *[ed25519.PublicKeySize]byte, payload []byte, signature *[ed25519.SignatureSize]byte) error {
	m.l.Lock()
	defer m.l.Unlock()
	waiting, ok := m.waiting[*msgID]
	if !ok {
		return nil // nothing waiting is not an error
	}
	delete(m.waiting, *msgID)
	m.log.Debugf("Woke %d: %x", len(waiting), msgID)

	// prepare the response payload for pending requests
	scratchResponse := &common.ScratchResponse{Status: common.StatusOK, Payload: payload, Signature: *signature}
	rawResp, err := scratchResponse.Marshal()
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
func (m *Scratch) Get(msgID *[ed25519.PublicKeySize]byte) ([]byte, *[ed25519.SignatureSize]byte, error) {
	sig := new([ed25519.SignatureSize]byte)
	var resp []byte
	err := m.db.View(func(tx *bolt.Tx) error {
		scratchBkt := tx.Bucket([]byte(scratchBucket))
		if scratchBkt == nil {
			return errors.New("scratchBucket does not exist")
		}
		p := scratchBkt.Get(msgID[:])
		if p == nil {
			// empty slot
			return common.ErrStatusNotFound
		}
		resp = make([]byte, len(p[ed25519.SignatureSize:]))
		copy(resp, p[ed25519.SignatureSize:])
		copy(sig[:], p[:ed25519.SignatureSize])
		return nil
	})
	return resp, sig, err
}

// Put places an item in the db
func (m *Scratch) Put(msgID *[ed25519.PublicKeySize]byte, payload []byte, sig *[ed25519.SignatureSize]byte) error {
	err := m.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(scratchBucket))
		p := bkt.Get(msgID[:])
		if p != nil {
			if !bytes.Equal(p, payload) {
				m.log.Errorf("Got different payload for %x", msgID[:])
			}
		}

		// store message in scratchBucket
		err := bkt.Put(msgID[:], append(sig[:], payload...))
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

// GarbageCollect prunes the oldest bucket of entries when the scratch size limit is exceeded
func (m *Scratch) GarbageCollect() error {
	return m.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(gcBucket))
		size := bkt.Stats().InlineBucketN * m.gcSize
		if size > m.scratchSize {
			// delete scratch entries in the oldest gcBkt
			k, _ := bkt.Cursor().First()
			gcbkt := bkt.Bucket(k)
			mbkt := tx.Bucket([]byte(scratchBucket))
			gcbkt.ForEach(func(k, v []byte) error {
				return mbkt.Delete(k)
			})
			bkt.DeleteBucket(k)
		}
		return nil
	})
}

func (m *Scratch) Shutdown() {
	m.db.Close()
	m.Halt()
}

func (m *Scratch) worker() {
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

// NewScratch instantiates a scratch
func NewScratch(fileStore string, log *logging.Logger, gcSize int, scratchSize int) (*Scratch, error) {
	m := &Scratch{
		l:              new(sync.Mutex),
		log:            log,
		scratchSize:    scratchSize,
		gcSize:         gcSize,
		waiting:        make(map[[ed25519.PublicKeySize]byte][]*cborplugin.Response),
	}
	db, err := bolt.Open(fileStore, 0600, nil)
	if err != nil {
		log.Errorf("%s", err)
		return nil, err
	}
	m.db = db
	if err = m.db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(scratchBucket)); err != nil {
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

func (m *Scratch) OnCommand(cmd cborplugin.Command) error {
	switch r := cmd.(type) {
	case *cborplugin.Request:
		if r.SURB == nil {
			return errors.New("no SURB, cannot reply")
		}
		req := &common.ScratchRequest{}
		dec := cbor.NewDecoder(bytes.NewReader(r.Payload))
		err := dec.Decode(req)
		if err != nil {
			return err
		}

		resp := &common.ScratchResponse{}

		// Verify if payload present
		if len(req.Payload) > 0 && validateBacap(req) {
			m.log.Debugf("Put(%x)", req.ID)

			// save payload
			err := m.Put(&req.ID, req.Payload, &req.Signature)
			if err != nil {
				m.log.Debugf("Put(%x): Failed", req.ID)
				resp.Status = common.StatusFailed
			} else {
				m.log.Debugf("Put(%x): OK", req.ID)
				resp.Status = common.StatusOK
			}

			// Wake pending Get requests and respond with payload
			err = m.Wake(&req.ID, req.Payload, &req.Signature)
			if err != nil {
				m.log.Errorf("Wake(%x): %v", req.ID, err)
			}

			// Otherwise return data
		} else {
			p, sig, err := m.Get(&req.ID)
			if err != nil {
				m.log.Debugf("m.Get(%x): %v", req.ID, err)
				// wait for future data
				m.Wait(&req.ID, &cborplugin.Response{ID: r.ID, SURB: r.SURB})
				// do not use SURB, return nil
				return nil
			} else {
				// data was found, respond immediately
				m.log.Debugf("Get(%x): OK", req.ID)
				resp.Status = common.StatusOK
				resp.Payload = p
				resp.Signature = *sig
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

func validateBacap(req *common.ScratchRequest) bool {
	var boxPk ed25519.PublicKey
	if err := boxPk.FromBytes(req.ID[:]); err != nil {
		return false
	}
	return boxPk.Verify(req.Signature[:], req.Payload)
}

func (m *Scratch) RegisterConsumer(svr *cborplugin.Server) {
	m.write = svr.Write
}
