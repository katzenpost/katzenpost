// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica_service

import (
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/replica_service/config"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

type ReplicaService struct {
	worker.Worker

	cfg *config.Config

	logBackend *log.Backend
	write      func(cborplugin.Command)
	log        *logging.Logger
}

func New(cfg *config.Config) (*ReplicaService, error) {
	return &ReplicaService{}, nil // XXX FIX ME
}

func (r *ReplicaService) Shutdown() {
	r.Halt()
}

// RotateLog rotates the log file
// if logging to a file is enabled.
func (r *ReplicaService) RotateLog() {
	r.logBackend.Rotate()
}

/*** cbor mixnet service plugin methods below here ***/

func (r *ReplicaService) OnCommand(cmd cborplugin.Command) error {
	// XXX TODO
	return nil
}

func (r *ReplicaService) RegisterConsumer(s *cborplugin.Server) {
	r.write = s.Write
}

func (r *ReplicaService) SetWriteFunc(writeFunc func(cborplugin.Command)) {
	r.write = writeFunc
}
