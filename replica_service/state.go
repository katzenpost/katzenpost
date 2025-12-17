// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica_service

import (
	"errors"
	"path/filepath"

	"github.com/linxGnu/grocksdb"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/pigeonhole"
	"github.com/katzenpost/katzenpost/replica_service/config"
)

const (
	errDatabaseClosed = "database is closed"
)

var (
	ErrBoxIDNotFound       = errors.New("box ID not found")
	ErrFailedDBRead        = errors.New("failed to read from database")
	ErrFailedToDeserialize = errors.New("failed to deserialize data from DB")
	ErrDBClosed            = errors.New("database is closed")
)

type state struct {
	cfg *config.Config
	db  *grocksdb.DB
	log *logging.Logger
}

func newState(cfg *config.Config, log *logging.Logger) *state {
	if cfg.SphinxGeometry == nil {
		panic("cfg.SphinxGeometry cannot be nil")
	}
	st := &state{
		cfg: cfg,
		log: log,
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
	path := filepath.Join(s.cfg.DataDir, "replica_service.db")
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

func (s *state) handleReplicaRead(replicaRead *pigeonhole.ReplicaRead) (*pigeonhole.Box, error) {
	s.log.Debugf("state: Starting replica read for BoxID: %x", replicaRead.BoxID)

	// Check if database is still open
	if s.db == nil {
		s.log.Error("state: Database is closed, cannot perform read")
		return nil, ErrDBClosed
	}

	ro := grocksdb.NewDefaultReadOptions()
	defer ro.Destroy()

	s.log.Debug("state: Attempting database read")
	value, err := s.db.Get(ro, replicaRead.BoxID[:])
	if err != nil {
		s.log.Errorf("state: Failed to read from database: %s", err)
		return nil, ErrFailedDBRead
	}
	if value.Size() == 0 {
		s.log.Debugf("state: No data found for BoxID: %x", replicaRead.BoxID)
		return nil, ErrBoxIDNotFound
	}
	s.log.Debugf("state: Successfully read %d bytes from database", value.Size())
	data := make([]byte, value.Size())
	copy(data, value.Data())
	value.Free()

	box, err := pigeonhole.BoxFromBytes(data)
	if err != nil {
		s.log.Errorf("state: Failed to deserialize box: %s", err)
		return nil, ErrFailedToDeserialize
	}
	s.log.Debugf("state: Successfully handled replica read, returning box with %d bytes payload", len(box.Payload))
	return box, nil
}

func (s *state) handleReplicaWrite(replicaWrite *pigeonhole.ReplicaWrite) error {
	s.log.Debugf("state: Starting replica write for BoxID: %x", replicaWrite.BoxID)

	// Check if database is still open
	if s.db == nil {
		s.log.Error("state: Database is closed, cannot perform write")
		return errors.New(errDatabaseClosed)
	}

	wo := grocksdb.NewDefaultWriteOptions()
	defer wo.Destroy()
	box := &pigeonhole.Box{
		PayloadLen: uint32(len(replicaWrite.Payload)),
		Payload:    replicaWrite.Payload,
	}
	// Convert types
	copy(box.BoxID[:], replicaWrite.BoxID[:])
	copy(box.Signature[:], replicaWrite.Signature[:])
	s.log.Debugf("state: Attempting to write %d bytes to database", len(box.Bytes()))
	err := s.db.Put(wo, box.BoxID[:], box.Bytes())
	if err != nil {
		s.log.Errorf("state: Failed to write to database: %s", err)
		return err
	}
	s.log.Debug("state: Successfully handled replica write")
	return nil
}

// XXX TODO REPLICATION: Missing Rebalance() method which scans all Box IDs,
// determines which shards they belong to, and dispatches write commands
// to remote replicas for redundancy. See replica/state.go Rebalance().
// Also missing getRemoteShards() which uses PKI document to determine
// which storage replicas should hold copies of a given BoxID.
