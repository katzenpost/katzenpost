// storage.go - PANDA Kaetzchen service storage.
// Copyright (C) 2018, 2019  David Stainton.
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
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/panda/common"
	bolt "go.etcd.io/bbolt"
)

const (
	// PandaStorageVersion is the version of our on disk format.
	PandaStorageVersion = 0

	metadataBucket  = "metadata"
	versionKey      = "version"
	postsBucketName = "posts"
	postTimeKey     = "time"
	postAKey        = "A"
	postBKey        = "B"
)

// PandaPosting is the data structure stored on Panda
// server with each client interaction.
type PandaPosting struct {
	sync.Mutex

	Dirty    bool
	UnixTime int64
	A, B     []byte
}

// Expired returns true if the posting is
// older than the specified expiration duration.
func (p *PandaPosting) Expired(expiration time.Duration) bool {
	postingTime := time.Unix(p.UnixTime, 0)
	return time.Now().After(postingTime.Add(expiration))
}

func postingFromRequest(req *common.PandaRequest) (*[common.PandaTagLength]byte, *PandaPosting, error) {
	tagRaw, err := hex.DecodeString(req.Tag)
	if err != nil {
		return nil, nil, err
	}
	if len(tagRaw) != common.PandaTagLength {
		return nil, nil, errors.New("postingFromRequest failure: tag not 32 bytes in length")
	}
	message, err := base64.StdEncoding.DecodeString(req.Message)
	if err != nil {
		return nil, nil, err
	}
	p := &PandaPosting{
		UnixTime: time.Now().Unix(),
		A:        message,
		B:        nil,
	}
	tag := [common.PandaTagLength]byte{}
	copy(tag[:], tagRaw)
	return &tag, p, nil
}

// PandaStorage handles the on disk persistence for the PANDA server.
type PandaStorage struct {
	worker.Worker

	// [common.PandaTagLength]byte -> *PandaPosting
	postings          *sync.Map
	db                *bolt.DB
	dwellDuration     time.Duration
	writeBackInterval time.Duration
}

// NewPandaStorage creates an in memory store
// for Panda postings
func NewPandaStorage(fileStore string, dwellDuration time.Duration, writeBackInterval time.Duration) (*PandaStorage, error) {
	s := &PandaStorage{
		dwellDuration:     dwellDuration,
		writeBackInterval: writeBackInterval,
		postings:          new(sync.Map),
	}
	var err error
	s.db, err = bolt.Open(fileStore, 0600, nil)
	if err != nil {
		return nil, err
	}
	if err = s.db.Update(func(tx *bolt.Tx) error {
		var metaBucket *bolt.Bucket
		var postsBucket *bolt.Bucket
		metaBucket, err = tx.CreateBucketIfNotExists([]byte(metadataBucket))
		if err != nil {
			return err
		}
		if postsBucket, err = tx.CreateBucketIfNotExists([]byte(postsBucketName)); err != nil {
			return err
		}

		if b := metaBucket.Get([]byte(versionKey)); b != nil {
			// database loaded
			if len(b) != 1 || b[0] != PandaStorageVersion {
				return fmt.Errorf("spool storage: incompatible version: %d", uint(b[0]))
			}
			return s.load(tx, postsBucket)
		}
		// database created
		return metaBucket.Put([]byte(versionKey), []byte{PandaStorageVersion})
	}); err != nil {
		s.db.Close()
		return nil, err
	}
	s.Go(s.worker)
	return s, nil
}

func (s *PandaStorage) load(tx *bolt.Tx, postsBucket *bolt.Bucket) error {
	c := postsBucket.Cursor()
	for tag, value := c.First(); tag != nil; tag, value = c.Next() {
		if value != nil {
			return errors.New("posting entry value should be nil")
		}
		postingBucket := postsBucket.Bucket(tag)
		if postingBucket == nil {
			return errors.New("posting bucket does not exist")
		}
		rawTime := postingBucket.Get([]byte(postTimeKey))
		if rawTime == nil {
			return errors.New("time not found")
		}
		a := postingBucket.Get([]byte(postAKey))
		if a == nil {
			return errors.New("posting A not found")
		}
		b := postingBucket.Get([]byte(postBKey))
		if b == nil {
			return errors.New("posting B not found")
		}
		posting := PandaPosting{
			Dirty:    false,
			UnixTime: int64(binary.BigEndian.Uint64(rawTime)),
			A:        a,
			B:        b,
		}
		tagArray := [common.PandaTagLength]byte{}
		copy(tagArray[:], tag)
		s.postings.Store(tagArray, posting)
	}
	return nil
}

func (s *PandaStorage) worker() {
	defer func() {
		err := s.Vacuum()
		if err != nil {
			// no logger here? too fucking bad
			//panic(err)
			return
		}
	}()
	ticker := time.NewTicker(s.writeBackInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.HaltCh():
			return
		case <-ticker.C:
		}
		err := s.Vacuum()
		if err != nil {
			// no logger here? too fucking bad
			continue
			//panic(err)
		}
	}
}

func (s *PandaStorage) doFlush() error {
	var err error
	postingsRange := func(rawTag, rawPosting interface{}) bool {
		posting, ok := rawPosting.(*PandaPosting)
		if !ok {
			err = errors.New("malformed posting")
			return false
		}
		posting.Lock()
		defer posting.Unlock()
		if !posting.Dirty {
			return true
		}
		tag, ok := rawTag.([common.PandaTagLength]byte)
		if !ok {
			err = errors.New("malformed tag")
			return false
		}
		if err = s.db.Update(func(tx *bolt.Tx) error {
			postsBucket := tx.Bucket([]byte(postsBucketName))
			if postsBucket == nil {
				return errors.New("posts bucket does not exist")
			}
			postingBucket, err := postsBucket.CreateBucketIfNotExists(tag[:])
			if err != nil {
				return err
			}
			rawTime := [8]byte{}
			binary.BigEndian.PutUint64(rawTime[:], uint64(posting.UnixTime))
			err = postingBucket.Put([]byte(postTimeKey), rawTime[:])
			if err != nil {
				return err
			}
			err = postingBucket.Put([]byte(postAKey), posting.A)
			if err != nil {
				return err
			}
			err = postingBucket.Put([]byte(postBKey), posting.B)
			if err != nil {
				return err
			}
			posting.Dirty = false
			s.postings.Store(tag, posting)
			return nil
		}); err != nil {
			return false
		}
		return true
	}
	s.postings.Range(postingsRange)
	err = s.doPurge()
	return err
}

func (s *PandaStorage) doPurge() error {
	var err error
	if err = s.db.Update(func(tx *bolt.Tx) error {
		postsBucket := tx.Bucket([]byte(postsBucketName))
		if postsBucket == nil {
			return errors.New("posts bucket does not exist")
		}
		c := postsBucket.Cursor()
		for tag, value := c.First(); tag != nil; tag, value = c.Next() {
			if value != nil {
				return errors.New("posting entry value should be nil")
			}
			postingBucket := postsBucket.Bucket(tag)
			if postingBucket == nil {
				return errors.New("posting bucket does not exist")
			}
			tagArray := [common.PandaTagLength]byte{}
			copy(tagArray[:], tag)
			_, ok := s.postings.Load(tagArray)
			if !ok {
				err = postsBucket.DeleteBucket(tag)
				if err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		s.db.Close()
		return err
	}
	return nil
}

// Shutdown stops the worker thread and sync the db.
func (s *PandaStorage) Shutdown() {
	s.doFlush()
	s.Halt()
	err := s.db.Sync()
	if err != nil {
		panic(err)
	}
	err = s.db.Close()
	if err != nil {
		panic(err)
	}
}

// Put stores a posting in the data store
// such that it is referenced by the given tag.
func (s *PandaStorage) Put(tag *[common.PandaTagLength]byte, posting *PandaPosting) error {
	posting.Dirty = true
	_, loaded := s.postings.LoadOrStore(*tag, posting)
	if loaded {
		return errors.New("PandaStorage Put failure: tag already present")
	}
	return nil
}

// Get returns a posting from the data store
// that is referenced by the given tag.
func (s *PandaStorage) Get(tag *[common.PandaTagLength]byte) (*PandaPosting, error) {
	message, ok := s.postings.Load(*tag)
	if !ok {
		return nil, common.ErrNoSuchPandaTag
	}
	posting, ok := message.(*PandaPosting)
	if !ok {
		return nil, errors.New("Get failure, invalid posting retreived from sync.Map")
	}
	return posting, nil
}

// Replace replaces the stored posting.
func (s *PandaStorage) Replace(tag *[common.PandaTagLength]byte, posting *PandaPosting) error {
	posting.Dirty = true
	s.postings.Store(*tag, posting)
	return nil
}

// Vacuum removes the postings that have expired.
func (s *PandaStorage) Vacuum() error {
	var err error
	postingsRange := func(rawTag, rawPosting interface{}) bool {
		tag, ok := rawTag.([common.PandaTagLength]byte)
		if !ok {
			err = errors.New("Vacuum failure, invalid tag retreived from sync.Map")
			return false
		}
		posting, ok := rawPosting.(*PandaPosting)
		if !ok {
			err = errors.New("Vacuum failure, invalid tag retreived from sync.Map")
			return false
		}
		posting.Lock()
		defer posting.Unlock()
		if posting.Expired(s.dwellDuration) {
			s.postings.Delete(tag)
		}
		return true
	}
	s.postings.Range(postingsRange)
	if err != nil {
		return err
	}
	return s.doFlush()
}
