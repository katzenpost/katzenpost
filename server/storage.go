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
	"time"
)

type InMemoryPandaStorage struct {
	postMap map[[PandaTagLength]byte]*PandaPosting
}

// NewInMemoryPandaStorage creates an in memory store
// for Panda postings
func NewInMemoryPandaStorage() *InMemoryPandaStorage {
	s := &InMemoryPandaStorage{
		postMap: make(map[[PandaTagLength]byte]*PandaPosting),
	}
	return s
}

// Put stores a posting in the data store
// such that it is referenced by the given tag.
func (s *InMemoryPandaStorage) Put(tag *[PandaTagLength]byte, posting *PandaPosting) error {
	_, ok := s.postMap[*tag]
	if ok {
		return errors.New("InMemoryPandaStorage Put failure: tag already present")
	}
	s.postMap[*tag] = posting
	return nil
}

// Get returns a posting from the data store
// that is referenced by the given tag.
func (s *InMemoryPandaStorage) Get(tag *[PandaTagLength]byte) (*PandaPosting, error) {
	message, ok := s.postMap[*tag]
	if !ok {
		return nil, ErrNoSuchPandaTag
	}
	return message, nil
}

// Replace replaces the stored posting.
func (s *InMemoryPandaStorage) Replace(tag *[PandaTagLength]byte, posting *PandaPosting) error {
	s.postMap[*tag] = posting
	return nil
}

// Vacuum removes the postings that have expired.
func (s *InMemoryPandaStorage) Vacuum(expiration time.Duration) error {
	for tag, posting := range s.postMap {
		if posting.Expired(expiration) {
			delete(s.postMap, tag)
		}
	}
	return nil
}
