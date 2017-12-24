// client.go - Katzenpost client library
// Copyright (C) 2017  David Stainton, Yawning Angel
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package client provides the Katzenpost midclient
package client

import (
	"fmt"

	"github.com/katzenpost/core/log"
	cpki "github.com/katzenpost/core/pki"
	"github.com/op/go-logging"
)

// Config is a client configuration.
type Config struct {
	// LogBackend is the logging backend to use for client logging.
	LogBackend *log.Backend

	// PKIClient is the PKI Document data source.
	PKIClient cpki.Client

	// Name to show logs
	Name string
}

func (cfg *Config) validate() error {
	if cfg.LogBackend == nil {
		return fmt.Errorf("minclient: no LogBackend provided")
	}
	if cfg.PKIClient == nil {
		return fmt.Errorf("minclient: no PKIClient provided")
	}
	return nil
}

// Client handles sending and receiving messages over the mix network
type Client struct {
	cfg *Config
	log *logging.Logger
}

// New creates a new Client with the provided configuration.
func New(cfg *Config) (*Client, error) {
	var err error
	if err = cfg.validate(); err != nil {
		return nil, err
	}
	c := new(Client)
	c.cfg = cfg
	c.log = c.cfg.LogBackend.GetLogger(fmt.Sprintf("Client_%s", c.cfg.Name))

	return c, nil
}
