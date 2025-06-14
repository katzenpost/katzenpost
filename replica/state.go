// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"fmt"
	"path/filepath"

	"github.com/linxGnu/grocksdb"
	"golang.org/x/crypto/blake2b"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/replica/common"
)

const (
	errDatabaseClosed = "database is closed"
)

type state struct {
	server *Server
	db     *grocksdb.DB
	log    *logging.Logger
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
	var err error
	s.db, err = grocksdb.OpenDb(opts, s.dbPath())
	if err != nil {
		panic(err)
	}
	s.log.Debug("state: Database initialized successfully")
}

func (s *state) handleReplicaRead(replicaRead *common.ReplicaRead) (*common.Box, error) {
	s.log.Debugf("state: Starting replica read for BoxID: %x", replicaRead.BoxID)

	// Check if database is still open
	if s.db == nil {
		s.log.Error("state: Database is closed, cannot perform read")
		return nil, fmt.Errorf(errDatabaseClosed)
	}

	ro := grocksdb.NewDefaultReadOptions()
	defer ro.Destroy()

	s.log.Debug("state: Attempting database read")
	value, err := s.db.Get(ro, replicaRead.BoxID[:])
	if err != nil {
		s.log.Errorf("state: Failed to read from database: %s", err)
		return nil, err
	}
	if value.Size() == 0 {
		s.log.Debugf("state: No data found for BoxID: %x", replicaRead.BoxID)
		return nil, fmt.Errorf("no data found for BoxID")
	}
	s.log.Debugf("state: Successfully read %d bytes from database", value.Size())
	data := make([]byte, value.Size())
	copy(data, value.Data())
	value.Free()

	box, err := common.BoxFromBytes(data)
	if err != nil {
		s.log.Errorf("state: Failed to deserialize box: %s", err)
		return nil, fmt.Errorf("invalid data retrieved from database: %s", err)
	}
	s.log.Debugf("state: Successfully handled replica read, returning box with %d bytes payload", len(box.Payload))
	return box, nil
}

func (s *state) handleReplicaWrite(replicaWrite *commands.ReplicaWrite) error {
	s.log.Debugf("state: Starting replica write for BoxID: %x", replicaWrite.BoxID)

	// Check if database is still open
	if s.db == nil {
		s.log.Error("state: Database is closed, cannot perform write")
		return fmt.Errorf(errDatabaseClosed)
	}

	wo := grocksdb.NewDefaultWriteOptions()
	defer wo.Destroy()
	box := &common.Box{
		BoxID:     replicaWrite.BoxID,
		Signature: replicaWrite.Signature,
		IsLast:    replicaWrite.IsLast,
		Payload:   replicaWrite.Payload,
	}
	s.log.Debugf("state: Attempting to write %d bytes to database", len(box.Bytes()))
	err := s.db.Put(wo, box.BoxID[:], box.Bytes())
	if err != nil {
		s.log.Errorf("state: Failed to write to database: %s", err)
		return err
	}
	s.log.Debug("state: Successfully handled replica write")
	return nil
}

func (s *state) replicaWriteFromBlob(blob []byte) (*commands.ReplicaWrite, error) {
	s.log.Debugf("state: Converting blob of size %d to ReplicaWrite", len(blob))
	box, err := common.BoxFromBytes(blob)
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
	ret := &commands.ReplicaWrite{
		Cmds: cmds,

		BoxID:     box.BoxID,
		Signature: box.Signature,
		IsLast:    box.IsLast,
		Payload:   box.Payload,
	}
	s.log.Debugf("state: Successfully converted blob to ReplicaWrite with BoxID: %x", box.BoxID)
	return ret, nil
}

func (s *state) getRemoteShards(boxID []byte) ([]*pki.ReplicaDescriptor, error) {
	s.log.Debugf("state: Getting remote shards for BoxID: %x", boxID)
	doc := s.server.PKIWorker.PKIDocument()
	boxIDar := new([32]byte)
	copy(boxIDar[:], boxID)
	shards, err := common.GetRemoteShards(s.server.identityPublicKey, boxIDar, doc)
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
func (s *state) Rebalance() error {
	s.log.Debug("state: Starting rebalance operation")

	// Check if database is still open
	if s.db == nil {
		s.log.Error("state: Database is closed, cannot perform rebalance")
		return fmt.Errorf(errDatabaseClosed)
	}

	ro := grocksdb.NewDefaultReadOptions()
	ro.SetFillCache(false)

	it := s.db.NewIterator(ro)
	defer it.Close()

	boxCount := 0
	for it.Seek([]byte{0}); it.Valid(); it.Next() {
		key := it.Key()
		value := it.Value()

		s.log.Debugf("state: Processing key: %x with value size %d", key.Data(), value.Size())

		writeCmd, err := s.replicaWriteFromBlob(value.Data())
		if err != nil {
			s.log.Errorf("state: Failed to create ReplicaWrite from blob: %s", err)
			return err
		}

		boxID := key.Data()
		remoteShards, err := s.getRemoteShards(boxID)
		if err != nil {
			s.log.Errorf("state: Failed to get remote shards: %s", err)
			return err
		}

		for _, shard := range remoteShards {
			idHash := blake2b.Sum256(shard.IdentityKey)
			s.log.Debugf("state: Dispatching to shard with ID hash: %x", idHash)
			s.server.connector.DispatchCommand(writeCmd, &idHash)
		}

		key.Free()
		value.Free()
		boxCount++
	}

	s.log.Debugf("state: Rebalance completed, processed %d boxes", boxCount)
	return nil
}
