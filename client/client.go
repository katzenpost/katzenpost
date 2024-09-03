// client.go - Katzenpost client library
// Copyright (C) 2018  David Stainton.
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

// Package client provides a Katzenpost client library.
package client

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/worker"
)

const (
	initialPKIConsensusTimeout = 45 * time.Second
)

// Client handles sending and receiving messages over the mix network
type Client struct {
	worker.Worker

	cfg        *config.Config
	logBackend *log.Backend
	log        *logging.Logger
	fatalErrCh chan error
	haltOnce   *sync.Once

	sessions     []*Session
	sessionMutex *sync.Mutex
}

// GetConfig returns the client configuration
func (c *Client) GetConfig() *config.Config {
	return c.cfg
}

// PKIBootstrap returns a pkiClient and fetches a consensus.
func PKIBootstrap(ctx context.Context, c *Client, linkKey kem.PrivateKey) (pki.Client, *pki.Document, error) {
	// Retrieve a copy of the PKI consensus document.
	pkiClient, err := c.cfg.NewPKIClient(c.logBackend, c.cfg.UpstreamProxyConfig(), linkKey, c.cfg.SphinxGeometry)
	if err != nil {
		return nil, nil, err
	}
	currentEpoch, _, _ := epochtime.FromUnix(time.Now().Unix())
	doc, _, err := pkiClient.Get(ctx, currentEpoch)
	if err != nil {
		return nil, nil, err
	}
	return pkiClient, doc, nil
}

// SelectGatewayNode returns a descriptor of a gateway or an error.
func SelectGatewayNode(doc *pki.Document) (*pki.MixDescriptor, error) {
	// Pick a Provider that supports TrustOnFirstUse
	gateways := []*pki.MixDescriptor{}
	for _, provider := range doc.GatewayNodes {
		gateways = append(gateways, provider)
	}
	if len(gateways) == 0 {
		return nil, errors.New("no Providers supporting tofu-authenticated connections found in the consensus")
	}
	gateway := gateways[rand.NewMath().Intn(len(gateways))]
	return gateway, nil
}

// New creates a new Client with the provided configuration.
func New(cfg *config.Config) (*Client, error) {
	c := new(Client)
	c.cfg = cfg
	c.fatalErrCh = make(chan error)
	c.sessionMutex = new(sync.Mutex)
	c.haltOnce = new(sync.Once)

	if err := c.initLogging(); err != nil {
		return nil, err
	}

	c.log.Noticef("😼 Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY. 😼")

	// Start the fatal error watcher.
	// must not run under worker.Worker.Go because fatalErr calls Halt() which
	// blocks until all routines have returned, which would deadlock.
	go c.fatalErr()
	return c, nil
}

func (c *Client) fatalErr() {
	select {
	case <-c.HaltCh():
	case err, ok := <-c.fatalErrCh:
		if ok {
			c.log.Warningf("Shutting down due to error: %v", err)
			c.Shutdown()
		}
	}
}

func (c *Client) initLogging() error {
	f := c.cfg.Logging.File
	if !c.cfg.Logging.Disable && c.cfg.Logging.File != "" {
		if !filepath.IsAbs(f) {
			return errors.New("log file path must be absolute path")
		}
	}

	var err error
	c.logBackend, err = log.New(f, c.cfg.Logging.Level, c.cfg.Logging.Disable)
	if err == nil {
		c.log = c.logBackend.GetLogger("katzenpost/client")
	}
	return err
}

func (c *Client) GetBackendLog() *log.Backend {
	return c.logBackend
}

// GetLogger returns a new logger with the given name.
func (c *Client) GetLogger(name string) *logging.Logger {
	return c.logBackend.GetLogger(name)
}

// Shutdown cleanly shuts down a given Client instance.
func (c *Client) Shutdown() {
	c.haltOnce.Do(func() { c.halt() })
}

func (c *Client) halt() {
	c.log.Noticef("Starting graceful shutdown.")
	c.sessionMutex.Lock()
	for _, s := range c.sessions {
		s.Shutdown()
	}
	c.sessionMutex.Unlock()
	close(c.fatalErrCh)
	c.Halt()
}

// NewTOFUSession creates and returns a new ephemeral session or an error.
func (c *Client) NewTOFUSession(ctx context.Context) (*Session, error) {
	var (
		err     error
		doc     *pki.Document
		gateway *pki.MixDescriptor
		linkKey kem.PrivateKey
	)

	// generate a linkKey
	sch := schemes.ByName(c.cfg.WireKEMScheme)
	if sch == nil {
		return nil, fmt.Errorf("config specified scheme `%s` not found", c.cfg.WireKEMScheme)
	}
	_, linkKey, err = sch.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	// fetch a pki.Document
	pkiclient, doc, err := PKIBootstrap(ctx, c, linkKey)
	if err != nil {
		return nil, err
	}
	// choose a gateway
	if gateway, err = SelectGatewayNode(doc); err != nil {
		return nil, err
	}

	c.sessionMutex.Lock()
	defer c.sessionMutex.Unlock()
	sess, err := NewSession(ctx, pkiclient, doc, c.fatalErrCh, c.logBackend, c.cfg, linkKey, gateway)
	if err != nil {
		return nil, err
	}
	c.sessions = append(c.sessions, sess)
	return sess, err
}

// Returns a random Session from sessions
func (c *Client) Session() *Session {
	c.sessionMutex.Lock()
	defer c.sessionMutex.Unlock()
	if len(c.sessions) == 0 {
		return nil
	}
	s := c.sessions[rand.NewMath().Intn(len(c.sessions))]
	return s
}
