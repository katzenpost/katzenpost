// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel and David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package memspool implements the Katzenpost server user message spool in
// memory.  It keeps the semantics of the boltspool it replaces (entries are
// added, advanced, removed and vacuumed for the same reasons, in the same
// order), but nothing is written to disk, so the spool is empty after a
// restart.
package memspool

import (
	"errors"
	"fmt"
	"sync"

	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/server/spool"
)

var errClosed = errors.New("spool: closed")

type entry struct {
	msg    []byte
	surbID []byte // nil for a plain message
}

type memSpool struct {
	sync.Mutex

	// users maps a recipient ID to its FIFO queue.  A user whose queue is
	// drained is deleted, which Get cannot tell apart from an empty queue.
	users  map[string][]entry
	closed bool
}

// New creates an empty in-memory user message spool.
func New() spool.Spool {
	return &memSpool{users: make(map[string][]entry)}
}

func (s *memSpool) Close() {
	s.Lock()
	defer s.Unlock()
	s.closed = true
	s.users = nil
}

func (s *memSpool) StoreMessage(u, msg []byte) error {
	return s.doStore(u, nil, msg)
}

func (s *memSpool) StoreSURBReply(u []byte, id *[sConstants.SURBIDLength]byte, msg []byte) error {
	if id == nil {
		return fmt.Errorf("spool: SURBReply is missing ID")
	}
	return s.doStore(u, id, msg)
}

func (s *memSpool) doStore(u []byte, id *[sConstants.SURBIDLength]byte, msg []byte) error {
	if len(u) == 0 || len(u) > sConstants.RecipientIDLength {
		return fmt.Errorf("spool: invalid username: `%v`", u)
	}

	// Copy: callers reuse the packet buffer once this returns.
	e := entry{msg: append([]byte{}, msg...)}
	if id != nil {
		e.surbID = append([]byte{}, id[:]...)
	}

	s.Lock()
	defer s.Unlock()
	if s.closed {
		return errClosed
	}
	s.users[string(u)] = append(s.users[string(u)], e)
	return nil
}

// Get optionally discards the first entry of the user's spool and returns
// the (new) first entry.  remaining is a hint, as with boltspool: 1 if more
// entries follow the returned one, else 0.
func (s *memSpool) Get(u []byte, advance bool) (msg, surbID []byte, remaining int, err error) {
	s.Lock()
	defer s.Unlock()
	if s.closed {
		err = errClosed
		return
	}

	q := s.users[string(u)]
	if advance && len(q) > 0 {
		q[0] = entry{} // Release the discarded payload now.
		q = q[1:]
		if len(q) == 0 {
			delete(s.users, string(u))
		} else {
			s.users[string(u)] = q
		}
	}
	if len(q) == 0 {
		return
	}
	if len(q) > 1 {
		remaining = 1
	}

	// Return copies, as boltspool did, so the caller may keep or modify them.
	msg = append([]byte{}, q[0].msg...)
	if q[0].surbID != nil {
		surbID = append([]byte{}, q[0].surbID...)
	}
	return
}

func (s *memSpool) Remove(u []byte) error {
	s.Lock()
	defer s.Unlock()
	if s.closed {
		return errClosed
	}
	delete(s.users, string(u))
	return nil
}

func (s *memSpool) VacuumExpired(ignoreIdentities map[[sConstants.RecipientIDLength]byte]interface{}) error {
	s.Lock()
	defer s.Unlock()
	if s.closed {
		return errClosed
	}
	for u := range s.users {
		// Shorter IDs are zero padded, as boltspool did.
		key := [sConstants.RecipientIDLength]byte{}
		copy(key[:], u)
		if _, ok := ignoreIdentities[key]; ok {
			continue
		}
		delete(s.users, u)
	}
	return nil
}
