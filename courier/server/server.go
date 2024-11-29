// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"github.com/katzenpost/katzenpost/courier/server/config"
)

type Server struct {
	cfg *config.Config
}

func New(cfg *config.Config) (*Server, error) {
	return nil, nil // XXX FIXME
}
