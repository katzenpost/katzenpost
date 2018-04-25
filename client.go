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
	"path/filepath"
	"sync"

	"github.com/katzenpost/client/config"
	"github.com/katzenpost/client/internal/authority"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/utils"
	"github.com/katzenpost/core/worker"
	"gopkg.in/eapache/channels.v1"
	"gopkg.in/op/go-logging.v1"
)

// Client handles sending and receiving messages over the mix network
type Client struct {
	worker.Worker
	cfg *config.Config

	logBackend *log.Backend
	log        *logging.Logger

	authority *authority.Store

	fatalErrCh chan error
	eventCh    channels.Channel
	haltedCh   chan interface{}
	haltOnce   sync.Once
}

func (c *Client) initLogging() error {
	f := c.cfg.Logging.File
	if !c.cfg.Logging.Disable && c.cfg.Logging.File != "" {
		if !filepath.IsAbs(f) {
			f = filepath.Join(c.cfg.Proxy.DataDir, f)
		}
	}

	var err error
	c.logBackend, err = log.New(f, c.cfg.Logging.Level, c.cfg.Logging.Disable)
	if err == nil {
		c.log = c.logBackend.GetLogger("mailproxy")
	}
	return err
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
	c.log.Noticef("Starting graceful shutdown.")

	if c.authority != nil {
		c.authority.Reset()
		c.authority = nil
	}

	c.Halt()
	close(c.fatalErrCh)

	c.log.Noticef("Shutdown complete.")
	close(c.haltedCh)
}

// New creates a new Client with the provided configuration.
func New(cfg *config.Config) (*Client, error) {
	c := new(Client)
	c.cfg = cfg
	c.fatalErrCh = make(chan error)
	c.haltedCh = make(chan interface{})

	// Do the early initialization and bring up logging.
	if err := utils.MkDataDir(c.cfg.Proxy.DataDir); err != nil {
		return nil, err
	}
	if err := c.initLogging(); err != nil {
		return nil, err
	}

	c.log.Noticef("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")

	isOk := false
	defer func() {
		if !isOk {
			c.Shutdown()
		}
	}()

	// Start the fatal error watcher.
	go func() {
		err, ok := <-c.fatalErrCh
		if !ok {
			return
		}
		c.log.Warningf("Shutting down due to error: %v", err)
		c.Shutdown()
	}()

	var err error

	// Bring the authority cache online.
	c.authority = authority.NewStore(c.logBackend, c.cfg.UpstreamProxyConfig())
	if err = c.authority.Set("authority", c.cfg.Authority()); err != nil {
		c.log.Errorf("Failed to add authority to store: %v", err)
		return nil, err
	}
	c.log.Debug("Added authority.")

	return c, nil
}
