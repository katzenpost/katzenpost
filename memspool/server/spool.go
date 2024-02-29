// spool.go - memspool
// Copyright (C) 2019  David Stainton.
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
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	sha512 "crypto/sha512"

	bolt "go.etcd.io/bbolt"
	"gopkg.in/op/go-logging.v1"

	eddsa "github.com/katzenpost/hpqc/sign/ed25519"

	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/memspool/common"
)

const (
	metadataBucket = "metadata"
	versionKey     = "version"

	spoolsBucketName = "spools"
	messagesKey      = "message"
	spoolMetadataKey = "spoolMetadata"
	spoolPublicKey   = "spoolPublicKey"

	writeBackInterval = 30 * time.Second

	SpoolStorageVersion = 0
)

var (
	errSpoolAlreadyExists = errors.New("Spool Already Exists")
)

func HandleSpoolRequest(spoolMap *MemSpoolMap, request *common.SpoolRequest, log *logging.Logger) *common.SpoolResponse {
	log.Debug("start of handle spool request")
	spoolResponse := common.SpoolResponse{}
	spoolID := [common.SpoolIDSize]byte{}
	copy(spoolID[:], request.SpoolID[:])
	switch request.Command {
	case common.CreateSpoolCommand:
		log.Debug("create spool")
		publicKey := new(eddsa.PublicKey)
		err := publicKey.FromBytes(request.PublicKey)
		if err != nil {
			spoolResponse.Status = err.Error()
			log.Error(spoolResponse.Status)
			return &spoolResponse
		}
		spoolResponse.Status = common.StatusOK
		newSpoolID, err := spoolMap.CreateSpool(publicKey, request.Signature)
		if err != nil {
			spoolResponse.Status = err.Error()
			log.Error(spoolResponse.Status)
			return &spoolResponse
		}
		spoolResponse.SpoolID = *newSpoolID
	case common.PurgeSpoolCommand:
		log.Debug("purge spool")
		err := spoolMap.PurgeSpool(spoolID, request.Signature)
		spoolResponse.SpoolID = spoolID
		if err != nil {
			spoolResponse.Status = err.Error()
			log.Error(spoolResponse.Status)
			return &spoolResponse
		}
		spoolResponse.Status = common.StatusOK
	case common.AppendMessageCommand:
		log.Debugf("append to spool, with spool ID: %d", request.SpoolID)
		err := spoolMap.AppendToSpool(spoolID, request.Message)
		log.Debug("after call to AppendToSpool")
		spoolResponse.SpoolID = spoolID
		if err != nil {
			spoolResponse.Status = err.Error()
			log.Error(spoolResponse.Status)
			return &spoolResponse
		}
		spoolResponse.Status = common.StatusOK
	case common.RetrieveMessageCommand:
		log.Debug("read from spool")
		log.Debugf("before ReadFromSpool with message ID %d", request.MessageID)
		message, err := spoolMap.ReadFromSpool(spoolID, request.Signature, request.MessageID)
		log.Debug("after ReadFromSpool")
		spoolResponse.SpoolID = spoolID
		spoolResponse.MessageID = request.MessageID
		if err != nil {
			spoolResponse.Status = err.Error()
			log.Error(spoolResponse.Status)
			return &spoolResponse
		}
		spoolResponse.Status = common.StatusOK
		spoolResponse.Message = message
	}
	log.Debug("end of handle spool request")
	return &spoolResponse
}

type MemSpoolMap struct {
	worker.Worker

	spools *sync.Map
	db     *bolt.DB
	log    *logging.Logger
}

func NewMemSpoolMap(fileStore string, log *logging.Logger) (*MemSpoolMap, error) {
	m := &MemSpoolMap{
		spools: new(sync.Map),
		log:    log,
	}
	var err error
	m.db, err = bolt.Open(fileStore, 0600, nil)
	if err != nil {
		return nil, err
	}
	if err = m.db.Update(func(tx *bolt.Tx) error {
		var metaBucket *bolt.Bucket
		var spoolsBucket *bolt.Bucket
		metaBucket, err = tx.CreateBucketIfNotExists([]byte(metadataBucket))
		if err != nil {
			return err
		}
		if spoolsBucket, err = tx.CreateBucketIfNotExists([]byte(spoolsBucketName)); err != nil {
			return err
		}
		if b := metaBucket.Get([]byte(versionKey)); b != nil {
			// database loaded
			if len(b) != 1 || b[0] != SpoolStorageVersion {
				return fmt.Errorf("spool storage: incompatible version: %d", uint(b[0]))
			}
			err = m.load(tx, spoolsBucket)
			return err
		}
		// database created
		return metaBucket.Put([]byte(versionKey), []byte{SpoolStorageVersion})
	}); err != nil {
		m.db.Close()
		return nil, err
	}
	m.Go(m.worker)
	return m, nil
}

// load iterates over each spool in spoolsBucket
// and populates m.spools.
func (m *MemSpoolMap) load(tx *bolt.Tx, spoolsBucket *bolt.Bucket) error {
	m.log.Debug("loading existing db from disk")
	c := spoolsBucket.Cursor()
	for key, value := c.First(); key != nil; key, value = c.Next() {
		if value != nil {
			return errors.New("spoolsBucket entry value should be nil")
		}
		spoolBucket := spoolsBucket.Bucket(key)
		if spoolBucket == nil {
			return errors.New("spool bucket does not exist")
		}
		spoolMetadataBucket := spoolBucket.Bucket([]byte(spoolMetadataKey))
		if spoolMetadataBucket == nil {
			return errors.New("spool metadata bucket not found")
		}
		rawSpoolPubKey := spoolMetadataBucket.Get([]byte(spoolPublicKey))
		if rawSpoolPubKey == nil {
			return errors.New("spool key not found")
		}
		spoolID := [common.SpoolIDSize]byte{}
		copy(spoolID[:], key)
		spoolPubKey := new(eddsa.PublicKey)
		err := spoolPubKey.FromBytes(rawSpoolPubKey)
		if err != nil {
			return err
		}
		err = m.addSpoolToMap(spoolPubKey, &spoolID)
		if err != nil {
			return err
		}
		messagesBucket := spoolBucket.Bucket([]byte(messagesKey))
		if messagesBucket == nil {
			return errors.New("spool messages bucket not found")
		}
		cur := messagesBucket.Cursor()
		for k, v := cur.First(); k != nil; k, v = cur.Next() {
			if len(k) != common.MessageIDSize {
				return errors.New("invalid message ID encountered")
			}
			messageID := [common.MessageIDSize]byte{}
			copy(messageID[:], k)
			err := m.appendToSpoolWithMessageID(spoolID, messageID, v)
			if err != nil {
				return err
			}
		}
		raw_spool, ok := m.spools.Load(spoolID)
		if !ok {
			panic("wtf")
		}
		k, _ := cur.Last() // obtain the latest MessageID
		if k != nil {
			raw_spool.(*MemSpool).current = binary.BigEndian.Uint32(k[:])
		} // empty spool...
	}
	return nil
}

func (m *MemSpoolMap) addSpoolToMap(publicKey *eddsa.PublicKey, spoolID *[common.SpoolIDSize]byte) error {
	spool := NewMemSpool(publicKey)
	_, loaded := m.spools.LoadOrStore(*spoolID, spool)
	if loaded {
		return errSpoolAlreadyExists
	}
	return nil
}

func (m *MemSpoolMap) createSpoolBucket(publicKey *eddsa.PublicKey, spoolID *[common.SpoolIDSize]byte) error {
	err := m.db.Update(func(tx *bolt.Tx) error {
		spoolsBucket := tx.Bucket([]byte(spoolsBucketName))
		spoolBucket, err := spoolsBucket.CreateBucket(spoolID[:])
		if err != nil {
			return err
		}
		spoolMetadata, err := spoolBucket.CreateBucket([]byte(spoolMetadataKey))
		if err != nil {
			return err
		}
		err = spoolMetadata.Put([]byte(spoolPublicKey), publicKey.Bytes())
		if err != nil {
			return err
		}
		_, err = spoolBucket.CreateBucket([]byte(messagesKey))
		if err != nil {
			return err
		}
		return err
	})
	return err
}

// CreateSpool creates a new spool and returns a spool ID or an error.
func (m *MemSpoolMap) CreateSpool(publicKey *eddsa.PublicKey, signature []byte) (*[common.SpoolIDSize]byte, error) {
	if !publicKey.Verify(signature, publicKey.Bytes()) {
		return nil, errors.New("Spool creation failed, invalid signature")
	}
	spoolID := [common.SpoolIDSize]byte{}
	spoolhash := sha512.Sum512_256(publicKey.Bytes())
	copy(spoolID[:], spoolhash[:common.SpoolIDSize])
	err := m.addSpoolToMap(publicKey, &spoolID)
	if err == errSpoolAlreadyExists {
		return &spoolID, nil
	} else if err != nil {
		return nil, err
	}
	err = m.createSpoolBucket(publicKey, &spoolID)
	if err != nil {
		return nil, err
	}
	return &spoolID, nil
}

// PurgeSpool delete the spool associated with the given spool ID.
// Returns nil on success or an error.
func (m *MemSpoolMap) PurgeSpool(spoolID [common.SpoolIDSize]byte, signature []byte) error {
	raw_spool, ok := m.spools.Load(spoolID)
	if !ok {
		return errors.New("spool ID not found in spools map")
	}
	spool, ok := raw_spool.(*MemSpool)
	if !ok {
		return errors.New("invalid spool found")
	}
	if !spool.PublicKey().Verify(signature, spool.PublicKey().Bytes()) {
		return errors.New("invalid signature")
	}
	m.spools.Delete(spoolID)
	return nil
}

func (m *MemSpoolMap) appendToSpoolWithMessageID(spoolID [common.SpoolIDSize]byte, messageID [common.MessageIDSize]byte, message []byte) error {
	raw_spool, ok := m.spools.Load(spoolID)
	if !ok {
		m.log.Debugf("AppendToSpool: spool not found: %x", spoolID[:])
		return errors.New("AppendToSpool: spool not found")
	}
	spool, ok := raw_spool.(*MemSpool)
	if !ok {
		m.log.Debug("invalid spool found")
		return errors.New("invalid spool found")
	}
	id := binary.BigEndian.Uint32(messageID[:])
	spool.Put(id, message, false)
	return nil
}

func (m *MemSpoolMap) AppendToSpool(spoolID [common.SpoolIDSize]byte, message []byte) error {
	raw_spool, ok := m.spools.Load(spoolID)
	if !ok {
		m.log.Debugf("AppendToSpool: spool not found: %x", spoolID[:])
		return errors.New("AppendToSpool: spool not found")
	}
	spool, ok := raw_spool.(*MemSpool)
	if !ok {
		m.log.Debug("invalid spool found")
		return errors.New("invalid spool found")
	}
	spool.Append(message)
	return nil
}

func (m *MemSpoolMap) ReadFromSpool(spoolID [common.SpoolIDSize]byte, signature []byte, messageID uint32) ([]byte, error) {
	raw_spool, ok := m.spools.Load(spoolID)
	if !ok {
		return nil, errors.New("ReadFromSpool: spool not found")
	}
	spool, ok := raw_spool.(*MemSpool)
	if !ok {
		return nil, errors.New("invalid spool found")
	}
	if !spool.PublicKey().Verify(signature, spool.PublicKey().Bytes()) {
		return nil, errors.New("invalid signature")
	}
	payload, _, err := spool.Get(messageID)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func (m *MemSpoolMap) doFlush() {
	spoolsRange := func(rawSpoolID, rawSpool interface{}) bool {
		spool, ok := rawSpool.(*MemSpool)
		if !ok {
			m.log.Error("Fatal error, doFlush encountered invalid MemSpool, wtf")
			return false
		}

		spoolRange := func(rawMessageID, rawEntry interface{}) bool {
			entry, ok := rawEntry.(*SpoolEntry)
			if !ok {
				m.log.Error("invalid SpoolEntry, wtf")
				panic("invalid SpoolEntry, wtf")
			}
			if entry.Dirty {
				var err error
				err = m.db.Update(func(tx *bolt.Tx) error {
					var err error
					spools := tx.Bucket([]byte(spoolsBucketName))
					if spools == nil {
						return errors.New("spoolsBucket does not exist, wtf")
					}
					spoolID, ok := rawSpoolID.([common.SpoolIDSize]byte)
					if !ok {
						return errors.New("encountered invalid spool ID, wtf")
					}
					spoolBucket := spools.Bucket(spoolID[:])
					if spool == nil {
						err = m.createSpoolBucket(spool.publicKey, &spoolID)
						if err != nil {
							return err
						}
					}
					messageID, ok := rawMessageID.(uint32)
					if !ok {
						return errors.New("invalid message ID, wtf")
					}
					var msgID [4]byte
					binary.BigEndian.PutUint32(msgID[:], messageID)
					messagesBucket := spoolBucket.Bucket([]byte(messagesKey))
					if messagesBucket == nil {
						return errors.New("impossible error, messagesBucket is nil")
					}
					err = messagesBucket.Put(msgID[:], entry.Payload)
					if err != nil {
						return err
					}
					spool.Put(messageID, entry.Payload, false)
					return nil
				})
				if err != nil {
					panic(err)
				}
			}
			return true
		}

		spool.items.Range(spoolRange)
		return true
	}
	m.spools.Range(spoolsRange)
}

func (m *MemSpoolMap) worker() {
	defer m.doFlush()

	ticker := time.NewTicker(writeBackInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.HaltCh():
			return
		case <-ticker.C:
		}
		m.doFlush()
	}
}

func (m *MemSpoolMap) Shutdown() {
	m.log.Debug("halting spool worker and persisting db to disk")
	m.Halt()
	if err := m.db.Sync(); err != nil {
		panic(err)
	}
	m.db.Close()
}

type SpoolEntry struct {
	Payload []byte
	Dirty   bool
}

type MemSpool struct {
	publicKey *eddsa.PublicKey
	items     *sync.Map
	current   uint32
}

func NewMemSpool(publicKey *eddsa.PublicKey) *MemSpool {
	return &MemSpool{
		publicKey: publicKey,
		items:     new(sync.Map),
		current:   0,
	}
}

func (s *MemSpool) PublicKey() *eddsa.PublicKey {
	return s.publicKey
}

func (s *MemSpool) Append(message []byte) {
	current := atomic.AddUint32(&s.current, 1)
	s.Put(current, message, true)
}

func (s *MemSpool) Put(messageID uint32, message []byte, dirty bool) {
	entry := SpoolEntry{
		Payload: message,
		Dirty:   dirty,
	}
	s.items.Store(messageID, &entry)
}

// Get returns a message payload from the spool given
// a valid message ID. Second return value is the Dirty bool
// which is set to true if the message has not been written to disk.
// If returning an error then the Dirty return value is false.
func (s *MemSpool) Get(messageID uint32) ([]byte, bool, error) {
	raw_message, ok := s.items.Load(messageID)
	if !ok {
		return nil, false, fmt.Errorf("message ID %d not found", messageID)
	}
	entry, ok := raw_message.(*SpoolEntry)
	if !ok {
		return nil, false, errors.New("invalid message found")
	}
	return entry.Payload, entry.Dirty, nil
}
