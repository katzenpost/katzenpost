// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"errors"
	"path/filepath"

	"github.com/linxGnu/grocksdb"

	"github.com/katzenpost/katzenpost/core/wire/commands"
)

type state struct {
	server *Server
	db     *grocksdb.DB
}

func newState(s *Server) *state {
	if s.cfg.SphinxGeometry == nil {
		panic("s.server.cfg.SphinxGeometry cannot be nil")
	}
	return &state{
		server: s,
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

func (s *state) handleReplicaRead(replicaRead *commands.ReplicaRead) (*commands.ReplicaWrite, error) {
	ro := grocksdb.NewDefaultReadOptions()
	defer ro.Destroy()

	value, err := s.db.Get(ro, replicaRead.ID[:])
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

	return s.db.Put(wo, replicaWrite.ID[:], replicaWrite.ToBytes())
}
