// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"crypto/hmac"
	"errors"
	"path/filepath"

	"github.com/linxGnu/grocksdb"
	"golang.org/x/crypto/blake2b"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
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
	return &state{
		server: s,
		log:    s.LogBackend().GetLogger("state"),
	}
}

func (s *state) Close() {
	s.db.Close()
}

func (s *state) dbPath() string {
	return filepath.Join(s.server.cfg.DataDir, "replica.db")
}

func (s *state) initDB() {
	opts := grocksdb.NewDefaultOptions()
	opts.SetCreateIfMissing(true)
	var err error
	s.db, err = grocksdb.OpenDb(opts, s.dbPath())
	if err != nil {
		panic(err)
	}
}

func intoBoxID(boxID []byte) []byte {
	return append([]byte("box"), boxID...)
}

func fromBoxID(boxID []byte) []byte {
	if !hmac.Equal(boxID[:3], []byte("box")) {
		panic("boxID doesn't begin with 'box'")
	}
	return boxID[3:]
}

func (s *state) handleReplicaRead(replicaRead *commands.ReplicaRead) (*commands.ReplicaWrite, error) {
	ro := grocksdb.NewDefaultReadOptions()
	defer ro.Destroy()

	value, err := s.db.Get(ro, intoBoxID(replicaRead.ID[:]))
	if err != nil {
		return nil, err
	}
	data := make([]byte, value.Size())
	copy(data, value.Data())
	value.Free()

	cmds := commands.NewStorageReplicaCommands(s.server.cfg.SphinxGeometry)
	rawCmds, err := cmds.FromBytes(data)
	if err != nil {
		return nil, err
	}
	writeCmd, ok := rawCmds.(*commands.ReplicaWrite)
	if !ok {
		return nil, errors.New("invalid data retrieved from database")
	}
	return writeCmd, nil
}

func (s *state) handleReplicaWrite(replicaWrite *commands.ReplicaWrite) error {
	wo := grocksdb.NewDefaultWriteOptions()
	defer wo.Destroy()

	return s.db.Put(wo, intoBoxID(replicaWrite.ID[:]), replicaWrite.ToBytes())
}

func (s *state) replicaWriteFromBlob(blob []byte) (*commands.ReplicaWrite, error) {
	cmds := commands.NewStorageReplicaCommands(s.server.cfg.SphinxGeometry)
	rawCmds, err := cmds.FromBytes(blob)
	if err != nil {
		return nil, err
	}
	writeCmd, ok := rawCmds.(*commands.ReplicaWrite)
	if !ok {
		return nil, errors.New("invalid data retrieved from database")
	}
	return writeCmd, nil
}

func (s *state) getRemoteShards(boxID []byte) ([]*pki.ReplicaDescriptor, error) {
	doc := s.server.pkiWorker.PKIDocument()
	boxIDar := new([32]byte)
	copy(boxIDar[:], boxID)
	shards, err := s.server.GetRemoteShards(boxIDar, doc)
	if err != nil {
		s.log.Errorf("ERROR GetShards for boxID %x has failed: %s", boxID, err)
		return nil, err
	}
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
	ro := grocksdb.NewDefaultReadOptions()
	ro.SetFillCache(false)

	it := s.db.NewIterator(ro)
	defer it.Close()
	it.Seek([]byte("box"))

	for it = it; it.Valid(); it.Next() {
		key := it.Key()
		value := it.Value()

		writeCmd, err := s.replicaWriteFromBlob(value.Data())
		if err != nil {
			return err
		}

		boxID := fromBoxID(key.Data())
		remoteShards, err := s.getRemoteShards(boxID)
		if err != nil {
			return err
		}

		cmd := &commands.ReplicaWrite{
			ID:        writeCmd.ID,
			Signature: writeCmd.Signature,
			Payload:   writeCmd.Payload,
		}
		for _, shard := range remoteShards {
			idHash := blake2b.Sum256(shard.IdentityKey)
			s.server.connector.DispatchCommand(cmd, &idHash)
		}

		key.Free()
		value.Free()
	}

	return nil
}
