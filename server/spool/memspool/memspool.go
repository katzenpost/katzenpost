// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel and David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package memspool implements the Katzenpost server user message spool in
// memory.  It keeps the semantics of the boltspool it replaces (entries are
// added, advanced, removed and vacuumed for the same reasons, in the same
// order), but nothing is written to disk, so the spool is empty after a
// restart.
//
// Unlike boltspool it is bounded: a new entry that would take its recipient
// or the whole spool over a byte limit is refused, and the queue is left as
// it was.  Evicting old entries instead would break the client's view of the
// queue: a client acknowledges the head it was shown by advancing, so
// dropping the head behind its back makes that advance discard an entry it
// never saw.  A refused message is lost at the gateway like any other drop,
// and the sender's retransmission covers it.
package memspool

import (
	"errors"
	"fmt"
	"sync"

	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/server/internal/instrument"
	"github.com/katzenpost/katzenpost/server/spool"
)

var errClosed = errors.New("spool: closed")

type entry struct {
	msg    []byte
	surbID []byte // nil for a plain message
}

func (e *entry) size() int { return len(e.msg) + len(e.surbID) }

type queue struct {
	entries []entry
	bytes   int
}

type memSpool struct {
	sync.Mutex

	// users maps a recipient ID to its FIFO queue.  A user whose queue is
	// drained is deleted, which Get cannot tell apart from an empty queue.
	users  map[string]*queue
	bytes  int
	closed bool

	maxRecipientBytes int
	maxBytes          int
}

// New creates an empty in-memory user message spool that holds at most
// maxRecipientBytes per recipient and maxBytes in total, counting message
// and SURB ID bytes.
func New(maxRecipientBytes, maxBytes int) spool.Spool {
	return &memSpool{
		users:             make(map[string]*queue),
		maxRecipientBytes: maxRecipientBytes,
		maxBytes:          maxBytes,
	}
}

// release drops a recipient's queue and its bytes.  Caller holds the lock.
func (s *memSpool) release(u string) {
	if q, ok := s.users[u]; ok {
		s.bytes -= q.bytes
		delete(s.users, u)
	}
}

func (s *memSpool) Close() {
	s.Lock()
	defer s.Unlock()
	s.closed = true
	s.users = nil
	s.bytes = 0
	instrument.GatewaySpoolBytes(0)
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

	n := e.size()

	s.Lock()
	defer s.Unlock()
	if s.closed {
		return errClosed
	}
	q := s.users[string(u)]
	if q == nil {
		q = new(queue)
	}
	if q.bytes+n > s.maxRecipientBytes {
		return fmt.Errorf("%w: %d bytes queued, %d more would pass the %d byte limit", spool.ErrRecipientFull, q.bytes, n, s.maxRecipientBytes)
	}
	if s.bytes+n > s.maxBytes {
		return fmt.Errorf("%w: %d bytes queued, %d more would pass the %d byte limit", spool.ErrFull, s.bytes, n, s.maxBytes)
	}
	q.entries = append(q.entries, e)
	q.bytes += n
	s.users[string(u)] = q
	s.bytes += n
	instrument.GatewaySpoolBytes(s.bytes)
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
	if q == nil {
		return
	}
	if advance {
		n := q.entries[0].size()
		q.entries[0] = entry{} // Release the discarded payload now.
		q.entries = q.entries[1:]
		q.bytes -= n
		s.bytes -= n
		instrument.GatewaySpoolBytes(s.bytes)
		if len(q.entries) == 0 {
			delete(s.users, string(u))
			return
		}
	}
	if len(q.entries) > 1 {
		remaining = 1
	}

	// Return copies, as boltspool did, so the caller may keep or modify them.
	head := q.entries[0]
	msg = append([]byte{}, head.msg...)
	if head.surbID != nil {
		surbID = append([]byte{}, head.surbID...)
	}
	return
}

func (s *memSpool) Remove(u []byte) error {
	s.Lock()
	defer s.Unlock()
	if s.closed {
		return errClosed
	}
	s.release(string(u))
	instrument.GatewaySpoolBytes(s.bytes)
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
		s.release(u)
	}
	instrument.GatewaySpoolBytes(s.bytes)
	return nil
}
