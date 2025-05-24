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

func (s *state) handleReplicaRead(replicaRead *common.ReplicaRead) (*common.Box, error) {
	ro := grocksdb.NewDefaultReadOptions()
	defer ro.Destroy()

	value, err := s.db.Get(ro, replicaRead.BoxID[:])
	if err != nil {
		return nil, err
	}
	data := make([]byte, value.Size())
	copy(data, value.Data())
	value.Free()

	box, err := common.BoxFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("invalid data retrieved from database: %s", err)
	}
	return box, nil
}

func (s *state) handleReplicaWrite(replicaWrite *commands.ReplicaWrite) error {
	wo := grocksdb.NewDefaultWriteOptions()
	defer wo.Destroy()
	box := &common.Box{
		BoxID:     replicaWrite.BoxID,
		Signature: replicaWrite.Signature,
		Payload:   replicaWrite.Payload,
	}
	return s.db.Put(wo, box.BoxID[:], box.Bytes())
}

func (s *state) replicaWriteFromBlob(blob []byte) (*commands.ReplicaWrite, error) {
	box, err := common.BoxFromBytes(blob)
	if err != nil {
		return nil, err
	}
	scheme := schemes.ByName(s.server.cfg.ReplicaNIKEScheme)
	if scheme == nil {
		panic(fmt.Sprintf("scheme %s doesn't exist", s.server.cfg.ReplicaNIKEScheme))
	}
	cmds := commands.NewStorageReplicaCommands(s.server.cfg.SphinxGeometry, scheme)
	ret := &commands.ReplicaWrite{
		Cmds: cmds,

		BoxID:     box.BoxID,
		Signature: box.Signature,
		Payload:   box.Payload,
	}
	return ret, nil
}

func (s *state) getRemoteShards(boxID []byte) ([]*pki.ReplicaDescriptor, error) {
	doc := s.server.pkiWorker.PKIDocument()
	boxIDar := new([32]byte)
	copy(boxIDar[:], boxID)
	shards, err := common.GetRemoteShards(s.server.identityPublicKey, boxIDar, doc)
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
	it.Seek([]byte{0})

	for it = it; it.Valid(); it.Next() {
		key := it.Key()
		value := it.Value()

		s.log.Debugf("key %v", key)

		writeCmd, err := s.replicaWriteFromBlob(value.Data())
		if err != nil {
			return err
		}

		boxID := key.Data()
		remoteShards, err := s.getRemoteShards(boxID)
		if err != nil {
			return err
		}

		for _, shard := range remoteShards {
			idHash := blake2b.Sum256(shard.IdentityKey)
			s.server.connector.DispatchCommand(writeCmd, &idHash)
		}

		key.Free()
		value.Free()
	}

	return nil
}
