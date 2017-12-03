// client.go - Minimal Katzenpost client.
// Copyright (C) 2017  Yawning Angel.
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

// Package minclient provides a minimal Katzenpost client.
package minclient

import (
	"fmt"
	"sync"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/log"
	cpki "github.com/katzenpost/core/pki"
	"github.com/op/go-logging"
)

// ClientConfig is a client configuration.
type ClientConfig struct {
	User, Provider string
	IdentityKey    *ecdh.PrivateKey

	LogBackend *log.Backend
	PKIClient  cpki.Client
}

// Client is a client instance.
type Client struct {
	cfg *ClientConfig
	log *logging.Logger

	pki  *pki
	conn *connection

	displayName string

	haltedCh chan interface{}
	haltOnce sync.Once
}

// Shutdown cleanly shuts down a given Client instance.
func (c *Client) Shutdown() {
	c.haltOnce.Do(func() { c.halt() })
}

// Wait waits till the Client is terminated for any reason.
func (c *Client) Wait() {
	<-c.haltedCh
}

func (c *Client) halt() {
	c.log.Notice("Starting graceful shutdown.")

	if c.conn != nil {
		c.conn.Halt()
		// nil out after the PKI is torn down due to a dependency.
	}

	if c.pki != nil {
		c.pki.Halt()
		c.pki = nil
	}
	c.conn = nil

	// XXX: Close the persistence.

	c.log.Notice("Shutdown complete.")
	close(c.haltedCh)
}

// New creates a new Client with the provided configuration.
func New(cfg *ClientConfig) (*Client, error) {
	c := new(Client)
	c.cfg = cfg
	c.displayName = fmt.Sprintf("%v@%v", c.cfg.User, c.cfg.Provider)
	c.log = cfg.LogBackend.GetLogger("minclient:" + c.displayName)
	c.haltedCh = make(chan interface{})

	c.log.Notice("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")
	c.log.Debugf("User/Provider is: %v", c.displayName)
	c.log.Debugf("User Identity Key is: %v", c.cfg.IdentityKey.PublicKey())

	// XXX: Initialize the persistence.

	c.pki = newPKI(c)
	c.conn = newConnection(c)

	return c, nil
}
