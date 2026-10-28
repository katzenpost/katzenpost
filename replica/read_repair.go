// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"sync"
	"time"

	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/pigeonhole"
)

const (
	// readRepairTTL is how long a replica remembers the box it served a
	// read for, so a courier's repair hint can name the box by the
	// read's envelope hash.
	readRepairTTL = 5 * time.Minute

	// maxReadRepairs bounds the reads remembered at once; the oldest is
	// forgotten first.
	maxReadRepairs = 8192
)

type readRepair struct {
	envHash [32]byte
	boxID   [32]byte
	at      time.Time
}

// readRepairs maps the envelope hashes of recently served reads to the
// boxes they read. Its zero value is ready to use.
type readRepairs struct {
	mu    sync.Mutex
	boxes map[[32]byte]readRepair
	order []readRepair
}

func (r *readRepairs) remember(envHash, boxID *[32]byte, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.boxes == nil {
		r.boxes = make(map[[32]byte]readRepair)
	}
	for len(r.order) > 0 && (len(r.boxes) >= maxReadRepairs || now.Sub(r.order[0].at) > readRepairTTL) {
		r.forgetOldest()
	}
	e := readRepair{envHash: *envHash, boxID: *boxID, at: now}
	r.boxes[e.envHash] = e
	r.order = append(r.order, e)
}

// forgetOldest drops the oldest queued read, unless its envelope hash
// was remembered again since.
func (r *readRepairs) forgetOldest() {
	old := r.order[0]
	r.order = r.order[1:]
	if cur, ok := r.boxes[old.envHash]; ok && cur.at.Equal(old.at) {
		delete(r.boxes, old.envHash)
	}
}

// take returns and forgets the box a read was served for.
func (r *readRepairs) take(envHash *[32]byte, now time.Time) ([32]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.boxes[*envHash]
	if !ok {
		return [32]byte{}, false
	}
	delete(r.boxes, *envHash)
	if now.Sub(e.at) > readRepairTTL {
		return [32]byte{}, false
	}
	return e.boxID, true
}

// repairFromHint handles a courier's hint that a shard peer answered
// box-not-found for a read this replica served: the box is replicated
// to its shard peers again.
func (s *Server) repairFromHint(envHash *[32]byte) {
	boxID, ok := s.readRepairs.take(envHash, time.Now())
	if !ok {
		return
	}
	box, err := s.state.stateHandleReplicaRead(&pigeonhole.ReplicaRead{BoxID: boxID})
	if err != nil {
		s.log.Debugf("read repair: box %x: %v", boxID[:8], err)
		return
	}
	s.log.Debugf("read repair: replicating box %x", boxID[:8])
	s.connector.DispatchReplication(&commands.ReplicaWrite{
		BoxID:     &box.BoxID,
		Signature: &box.Signature,
		Payload:   box.Payload,
	})
}
