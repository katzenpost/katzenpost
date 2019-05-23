// storage.go - PANDA Kaetzchen service storage.
// Copyright (C) 2018  David Stainton.
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

package main

import (
	"errors"
	"sync"
	"time"

	"github.com/katzenpost/panda/common"
)

type InMemoryPandaStorage struct {
	// *[common.PandaTagLength]byte -> *PandaPosting
	postings *sync.Map
}

// NewInMemoryPandaStorage creates an in memory store
// for Panda postings
func NewInMemoryPandaStorage() *InMemoryPandaStorage {
	s := &InMemoryPandaStorage{
		postings: new(sync.Map),
	}
	return s
}

// Put stores a posting in the data store
// such that it is referenced by the given tag.
func (s *InMemoryPandaStorage) Put(tag *[common.PandaTagLength]byte, posting *PandaPosting) error {
	_, loaded := s.postings.LoadOrStore(tag, posting)
	if loaded {
		return errors.New("InMemoryPandaStorage Put failure: tag already present")
	}
	return nil
}

// Get returns a posting from the data store
// that is referenced by the given tag.
func (s *InMemoryPandaStorage) Get(tag *[common.PandaTagLength]byte) (*PandaPosting, error) {
	message, ok := s.postings.Load(tag)
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
func (s *InMemoryPandaStorage) Replace(tag *[common.PandaTagLength]byte, posting *PandaPosting) error {
	s.postings.Store(tag, posting)
	return nil
}

// Vacuum removes the postings that have expired.
func (s *InMemoryPandaStorage) Vacuum(expiration time.Duration) error {
	var err error
	postingsRange := func(rawTag, rawPosting interface{}) bool {
		tag, ok := rawTag.(*[common.PandaTagLength]byte)
		if !ok {
			err = errors.New("Vacuum failure, invalid tag retreived from sync.Map")
			return false
		}
		posting, ok := rawPosting.(*PandaPosting)
		if !ok {
			err = errors.New("Vacuum failure, invalid tag retreived from sync.Map")
			return false
		}
		if posting.Expired(expiration) {
			s.postings.Delete(tag)
		}
		return true
	}
	s.postings.Range(postingsRange)
	return err
}
