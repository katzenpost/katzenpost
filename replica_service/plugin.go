// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica_service

import (
	"path/filepath"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/replica_service/config"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

type ReplicaService struct {
	worker.Worker

	cfg   *config.Config
	state *state

	logBackend *log.Backend
	write      func(cborplugin.Command)
	log        *logging.Logger
}

func New(cfg *config.Config) (*ReplicaService, error) {
	// Initialize logging
	p := cfg.Logging.File
	if !cfg.Logging.Disable && cfg.Logging.File != "" {
		if !filepath.IsAbs(p) {
			p = filepath.Join(cfg.DataDir, p)
		}
	}

	logBackend, err := log.New(p, cfg.Logging.Level, cfg.Logging.Disable)
	if err != nil {
		return nil, err
	}

	r := &ReplicaService{
		cfg:        cfg,
		logBackend: logBackend,
		log:        logBackend.GetLogger("replica_service"),
	}

	r.log.Notice("Starting Katzenpost Replica Service")

	// Initialize state (database)
	r.state = newState(cfg, logBackend.GetLogger("replica_service state"))
	r.state.initDB()

	return r, nil
}

func (r *ReplicaService) Shutdown() {
	r.log.Notice("Shutting down Replica Service")
	if r.state != nil {
		r.state.Close()
	}
	r.Halt()
}

// RotateLog rotates the log file
// if logging to a file is enabled.
func (r *ReplicaService) RotateLog() {
	r.logBackend.Rotate()
}

/** these two methods are for the cbor plugin **/

func (r *ReplicaService) RegisterConsumer(s *cborplugin.Server) {
	r.write = s.Write
}

func (r *ReplicaService) SetWriteFunc(writeFunc func(cborplugin.Command)) {
	r.write = writeFunc
}
