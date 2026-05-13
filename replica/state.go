// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/linxGnu/grocksdb"
	"golang.org/x/crypto/blake2b"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/pigeonhole"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

const (
	errDatabaseClosed = "database is closed"

	// keyEpochSize is the on-disk encoding length of the replica-epoch
	// prefix that distinguishes stored boxes by the week in which they
	// were written. Storage keys are <8-byte big-endian epoch> || <BoxID>.
	keyEpochSize = 8

	// boxIDOffset is where the BoxID begins inside an on-disk storage key.
	boxIDOffset = keyEpochSize

	// defaultCFName is RocksDB's implicit column family. Box records live here.
	defaultCFName = "default"

	// metadataCFName holds small replica-local bookkeeping records that
	// are not box data, e.g. the storage-replica-set fingerprint used to
	// decide whether a startup rebalance is necessary.
	metadataCFName = "metadata"
)

func epochPrefix(epoch uint64) []byte {
	p := make([]byte, keyEpochSize)
	binary.BigEndian.PutUint64(p, epoch)
	return p
}

func boxKey(epoch uint64, boxID []byte) []byte {
	k := make([]byte, keyEpochSize+len(boxID))
	binary.BigEndian.PutUint64(k[:keyEpochSize], epoch)
	copy(k[keyEpochSize:], boxID)
	return k
}

// keptEpochs returns the replica epochs whose boxes are still within
// the retention window, newest first. Boxes one week old are kept;
// those two weeks old are eligible for deletion.
func keptEpochs(current uint64) []uint64 {
	if current == 0 {
		return []uint64{0}
	}
	return []uint64{current, current - 1}
}

func currentReplicaEpoch() uint64 {
	e, _, _ := replicaCommon.ReplicaNow()
	return e
}

// boxLock is a per-BoxID mutex with a refCount. refCount is protected by
// state.locksMu, not by bl.mu: it tracks how many goroutines currently
// hold or are waiting on this entry so that releaseBoxLock can remove
// the map entry when the last holder leaves.
type boxLock struct {
	mu       sync.Mutex
	refCount int
}

var (
	ErrBoxIDNotFound       = errors.New("Box ID not found")
	ErrBoxAlreadyExists    = errors.New("BoxID already exists, writes are immutable")
	ErrFailedDBRead        = errors.New("Failed to read from database")
	ErrFailedToDeserialize = errors.New("Failed to deserialize data from DB")
	ErrDBClosed            = errors.New("DB is closed")
)

type state struct {
	worker.Worker

	server *Server
	db     *grocksdb.DB
	// metaCF references the metadata column family. Box reads and
	// writes go through the default CF via the un-suffixed Get/Put/
	// iterator helpers, so metaCF is only consulted for bookkeeping.
	metaCF *grocksdb.ColumnFamilyHandle
	log    *logging.Logger

	// locksMu protects boxLocks and every boxLock's refCount. Held only
	// briefly during a map lookup / refCount adjustment, not across
	// database I/O, so it does not serialize the actual write work.
	locksMu  sync.Mutex
	boxLocks map[[32]byte]*boxLock
}

// acquireBoxLock returns a locked per-BoxID mutex. The caller MUST
// call releaseBoxLock with the returned *boxLock and the same boxID
// exactly once, whether or not the critical section succeeded.
//
// A single top-level mutex (locksMu) covers both the map operation and
// the refCount bump so that a concurrent releaseBoxLock cannot delete
// the entry between LoadOrStore-equivalent and refCount++.
func (s *state) acquireBoxLock(boxID *[32]byte) *boxLock {
	key := *boxID
	s.locksMu.Lock()
	if s.boxLocks == nil {
		s.boxLocks = make(map[[32]byte]*boxLock)
	}
	bl, ok := s.boxLocks[key]
	if !ok {
		bl = &boxLock{}
		s.boxLocks[key] = bl
	}
	bl.refCount++
	s.locksMu.Unlock()
	bl.mu.Lock()
	return bl
}

// releaseBoxLock unlocks the per-BoxID mutex and drops the refCount,
// removing the map entry when the last holder leaves.
func (s *state) releaseBoxLock(bl *boxLock, boxID *[32]byte) {
	bl.mu.Unlock()
	key := *boxID
	s.locksMu.Lock()
	bl.refCount--
	if bl.refCount == 0 {
		delete(s.boxLocks, key)
	}
	s.locksMu.Unlock()
}

func newState(s *Server) *state {
	if s.cfg.SphinxGeometry == nil {
		panic("s.server.cfg.SphinxGeometry cannot be nil")
	}
	st := &state{
		server: s,
		log:    s.LogBackend().GetLogger("replica state"),
	}
	st.log.Debug("state: Created new state")
	return st
}

func (s *state) Close() {
	s.log.Debug("state: Closing state")
	s.Worker.Halt()
	if s.metaCF != nil {
		s.metaCF.Destroy()
		s.metaCF = nil
	}
	if s.db != nil {
		s.db.Close()
		s.db = nil
	}
}

func (s *state) dbPath() string {
	path := filepath.Join(s.server.cfg.DataDir, "replica.db")
	s.log.Debugf("state: Database path: %s", path)
	return path
}

func (s *state) initDB() {
	s.log.Debug("state: Initializing database")
	opts := grocksdb.NewDefaultOptions()
	opts.SetCreateIfMissing(true)
	opts.SetCreateIfMissingColumnFamilies(true)

	// Discover the column families already on disk. ListColumnFamilies
	// errors when the database does not yet exist; in that case we are
	// creating from scratch and need only the default family in the
	// initial open list (the metadata CF is appended below).
	existing, err := grocksdb.ListColumnFamilies(opts, s.dbPath())
	if err != nil {
		s.log.Debugf("state: ListColumnFamilies returned %s, treating as fresh database", err)
		existing = []string{defaultCFName}
	}

	hasMeta := false
	for _, name := range existing {
		if name == metadataCFName {
			hasMeta = true
			break
		}
	}
	cfNames := append([]string(nil), existing...)
	if !hasMeta {
		cfNames = append(cfNames, metadataCFName)
	}

	cfOpts := make([]*grocksdb.Options, len(cfNames))
	for i := range cfNames {
		cfOpts[i] = opts
	}

	db, handles, err := grocksdb.OpenDbColumnFamilies(opts, s.dbPath(), cfNames, cfOpts)
	if err != nil {
		panic(err)
	}
	s.db = db
	for i, name := range cfNames {
		switch name {
		case metadataCFName:
			s.metaCF = handles[i]
		default:
			handles[i].Destroy()
		}
	}
	if s.metaCF == nil {
		panic("state: metadata column family handle missing after open")
	}
	s.log.Debug("state: Database initialized successfully")
}

func (s *state) stateHandleReplicaRead(replicaRead *pigeonhole.ReplicaRead) (*pigeonhole.Box, error) {
	s.log.Debugf("state: Starting replica read for BoxID: %x", replicaRead.BoxID)

	// Check if database is still open
	if s.db == nil {
		s.log.Error("state: Database is closed, cannot perform read")
		return nil, ErrDBClosed
	}

	ro := grocksdb.NewDefaultReadOptions()
	defer ro.Destroy()

	// Storage is bucketed by replica epoch; a tombstone written in a
	// later epoch must shadow an earlier box, so we consult the kept
	// window newest-first and return the first hit.
	for _, ep := range keptEpochs(currentReplicaEpoch()) {
		key := boxKey(ep, replicaRead.BoxID[:])
		value, err := s.db.Get(ro, key)
		if err != nil {
			s.log.Errorf("state: Failed to read from database: %s", err)
			return nil, ErrFailedDBRead
		}
		if value.Size() == 0 {
			value.Free()
			continue
		}
		data := make([]byte, value.Size())
		copy(data, value.Data())
		value.Free()
		box, err := pigeonhole.BoxFromBytes(data)
		if err != nil {
			s.log.Errorf("state: Failed to deserialize box: %s", err)
			return nil, ErrFailedToDeserialize
		}
		s.log.Debugf("state: Successfully handled replica read at epoch %d, returning box with %d bytes payload", ep, len(box.Payload))
		return box, nil
	}
	s.log.Debugf("state: No data found for BoxID: %x", replicaRead.BoxID)
	return nil, ErrBoxIDNotFound
}

func (s *state) handleReplicaWrite(replicaWrite *commands.ReplicaWrite) error {
	s.log.Debugf("state: Starting replica write for BoxID: %x", replicaWrite.BoxID)

	// Check if database is still open
	if s.db == nil {
		s.log.Error("state: Database is closed, cannot perform write")
		return fmt.Errorf(errDatabaseClosed)
	}

	// Serialize check-and-put for this BoxID so concurrent writers
	// cannot both pass the existence check and both Put. The lock is
	// per-BoxID — unrelated writes do not contend.
	bl := s.acquireBoxLock(replicaWrite.BoxID)
	defer s.releaseBoxLock(bl, replicaWrite.BoxID)

	ro := grocksdb.NewDefaultReadOptions()
	defer ro.Destroy()
	cur := currentReplicaEpoch()

	// Writes are immutable; a duplicate by content within the retention
	// window is idempotent (the courier's K=2 path retries on lost
	// replies and the replication layer assumes this), and a mismatch
	// is rejected. We consult both retained epochs because a prior
	// write may have landed just before an epoch boundary.
	for _, ep := range keptEpochs(cur) {
		existing, err := s.db.Get(ro, boxKey(ep, replicaWrite.BoxID[:]))
		if err != nil {
			s.log.Errorf("state: Failed to check existing entry for BoxID %x: %s", replicaWrite.BoxID, err)
			return fmt.Errorf("failed to check existing entry: %w", err)
		}
		if existing.Size() == 0 {
			existing.Free()
			continue
		}
		storedBox, perr := pigeonhole.BoxFromBytes(existing.Data())
		existing.Free()
		if perr == nil &&
			bytes.Equal(storedBox.Payload, replicaWrite.Payload) &&
			storedBox.Signature == *replicaWrite.Signature {
			s.log.Debugf("state: BoxID %x idempotent write at epoch %d (matching payload+signature)", replicaWrite.BoxID, ep)
			return nil
		}
		s.log.Debugf("state: BoxID %x already exists at epoch %d with differing data, rejecting write", replicaWrite.BoxID, ep)
		return ErrBoxAlreadyExists
	}

	wo := grocksdb.NewDefaultWriteOptions()
	defer wo.Destroy()
	box := &pigeonhole.Box{
		PayloadLen: uint32(len(replicaWrite.Payload)),
		Payload:    replicaWrite.Payload,
	}
	copy(box.BoxID[:], replicaWrite.BoxID[:])
	copy(box.Signature[:], replicaWrite.Signature[:])
	s.log.Debugf("state: Attempting to write %d bytes to database at replica epoch %d", len(box.Bytes()), cur)
	if err := s.db.Put(wo, boxKey(cur, box.BoxID[:]), box.Bytes()); err != nil {
		s.log.Errorf("state: Failed to write to database: %s", err)
		return err
	}
	s.log.Debug("state: Successfully handled replica write")
	return nil
}

// handleReplicaTombstone stores a tombstone (empty payload with signature) in the database.
// Tombstones are BACAP messages with empty payloads that overwrite previously stored messages.
// This allows readers to verify the tombstone was intentionally created by the writer.
func (s *state) handleReplicaTombstone(boxID [32]uint8, signature [64]uint8) error {
	s.log.Debugf("state: Processing tombstone for BoxID: %x", boxID)

	// Check if database is still open
	if s.db == nil {
		s.log.Error("state: Database is closed, cannot perform tombstone write")
		return fmt.Errorf(errDatabaseClosed)
	}

	// Take the same per-BoxID lock as handleReplicaWrite so a tombstone
	// and a concurrent normal write for the same BoxID can't interleave
	// between the existence check and the Put.
	boxIDArr := boxID
	bl := s.acquireBoxLock(&boxIDArr)
	defer s.releaseBoxLock(bl, &boxIDArr)

	wo := grocksdb.NewDefaultWriteOptions()
	defer wo.Destroy()

	// Store the tombstone as a Box with empty payload
	box := &pigeonhole.Box{
		PayloadLen: 0,
		Payload:    nil,
	}
	copy(box.BoxID[:], boxID[:])
	copy(box.Signature[:], signature[:])

	cur := currentReplicaEpoch()
	s.log.Debugf("state: Writing tombstone to database for BoxID: %x at replica epoch %d", boxID, cur)
	if err := s.db.Put(wo, boxKey(cur, box.BoxID[:]), box.Bytes()); err != nil {
		s.log.Errorf("state: Failed to write tombstone for BoxID %x to database: %s", boxID, err)
		return err
	}

	s.log.Debugf("state: Successfully stored tombstone for BoxID: %x", boxID)
	return nil
}

func (s *state) replicaWriteFromBlob(blob []byte) (*commands.ReplicaWrite, error) {
	s.log.Debugf("state: Converting blob of size %d to ReplicaWrite", len(blob))
	box, err := pigeonhole.BoxFromBytes(blob)
	if err != nil {
		s.log.Errorf("state: Failed to deserialize box from blob: %s", err)
		return nil, err
	}
	scheme := schemes.ByName(s.server.cfg.ReplicaNIKEScheme)
	if scheme == nil {
		s.log.Errorf("state: Scheme %s doesn't exist", s.server.cfg.ReplicaNIKEScheme)
		panic(fmt.Sprintf("scheme %s doesn't exist", s.server.cfg.ReplicaNIKEScheme))
	}
	cmds := commands.NewStorageReplicaCommands(s.server.cfg.SphinxGeometry, scheme)
	// Convert array types to pointer types for wire commands
	boxID := &[32]byte{}
	copy(boxID[:], box.BoxID[:])

	signature := &[64]byte{}
	copy(signature[:], box.Signature[:])

	ret := &commands.ReplicaWrite{
		Cmds:      cmds,
		BoxID:     boxID,
		Signature: signature,
		Payload:   box.Payload,
	}
	s.log.Debugf("state: Successfully converted blob to ReplicaWrite with BoxID: %x", box.BoxID)
	return ret, nil
}

func (s *state) getRemoteShards(boxID []byte) ([]*pki.ReplicaDescriptor, error) {
	s.log.Debugf("state: Getting remote shards for BoxID: %x", boxID)
	doc := s.server.PKIWorker.LastCachedPKIDocument()

	// Check if PKI document has storage replicas
	if doc == nil {
		s.log.Debugf("state: No PKI document available yet, skipping remote shards for BoxID: %x", boxID)
		return []*pki.ReplicaDescriptor{}, nil
	}

	if doc.StorageReplicas == nil || len(doc.StorageReplicas) == 0 {
		s.log.Debugf("state: No storage replicas in PKI document yet, skipping remote shards for BoxID: %x", boxID)
		return []*pki.ReplicaDescriptor{}, nil
	}

	boxIDar := new([32]byte)
	copy(boxIDar[:], boxID)
	shards, err := replicaCommon.GetRemoteShards(s.server.identityPublicKey, boxIDar, doc)
	if err != nil {
		s.log.Errorf("state: GetShards for boxID %x has failed: %s", boxID, err)
		return nil, err
	}
	s.log.Debugf("state: Found %d remote shards", len(shards))
	return shards, nil
}

// Rebalance is called once we've been noticed that one or more
// storage replicas have been added or removed from the PKI document.
// We perform a rebalance in order to maintain redundancy of all
// pigeonhole storage boxes in the system.
//
// Scan through all the Box IDs and determine which
// shards they belong to. If this replica node is one of the shares,
// then just copy the share to the other replica. Otherwise copy
// the share to the two replicas.
func (s *state) Rebalance(trigger string) error {
	s.log.Noticef("state: starting rebalance (trigger=%s)", trigger)
	start := time.Now()

	if s.db == nil {
		s.log.Error("state: Database is closed, cannot perform rebalance")
		return fmt.Errorf(errDatabaseClosed)
	}

	ro := grocksdb.NewDefaultReadOptions()
	ro.SetFillCache(false)
	defer ro.Destroy()

	it := s.db.NewIterator(ro)
	defer it.Close()

	// Iterate only the kept epochs; anything outside the window is
	// about to be GCed and need not be replicated again.
	for _, ep := range keptEpochs(currentReplicaEpoch()) {
		prefix := epochPrefix(ep)
		for it.Seek(prefix); it.Valid(); it.Next() {
			key := it.Key()
			rawKey := key.Data()
			if !bytes.HasPrefix(rawKey, prefix) {
				key.Free()
				break
			}
			if len(rawKey) < boxIDOffset+32 {
				s.log.Errorf("state: malformed key (size %d) at epoch %d, skipping", len(rawKey), ep)
				key.Free()
				continue
			}
			boxID := make([]byte, 32)
			copy(boxID, rawKey[boxIDOffset:boxIDOffset+32])
			key.Free()

			value := it.Value()
			writeCmd, err := s.replicaWriteFromBlob(value.Data())
			value.Free()
			if err != nil {
				s.log.Errorf("state: Failed to create ReplicaWrite from blob: %s", err)
				return err
			}

			remoteShards, err := s.getRemoteShards(boxID)
			if err != nil {
				s.log.Errorf("state: Failed to get remote shards: %s", err)
				return err
			}
			for _, shard := range remoteShards {
				idHash := blake2b.Sum256(shard.IdentityKey)
				s.server.connector.DispatchCommand(writeCmd, &idHash)
			}
		}
	}

	s.log.Noticef("state: rebalance completed (trigger=%s, duration=%s)", trigger, time.Since(start))

	// Record the storage-replica-set fingerprint we just rebalanced
	// against. The startup path consults this marker to decide whether
	// a fresh rebalance is necessary on the next boot. We only reach
	// this point after the iterator completes without error, so a
	// partial rebalance is never credited as complete.
	if doc := s.server.PKIWorker.LastCachedPKIDocument(); doc != nil {
		fp := replicaSetFingerprint(doc)
		if err := s.storeLastRebalanceFingerprint(fp); err != nil {
			s.log.Warningf("state: failed to persist rebalance fingerprint: %s", err)
		}
	}
	return nil
}
