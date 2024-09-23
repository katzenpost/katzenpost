// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"sync"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/worker"
)

type state struct {
	sync.RWMutex
	worker.Worker

	s   *Server
	log *logging.Logger
}
