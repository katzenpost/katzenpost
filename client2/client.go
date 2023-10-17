// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"io"
	"sync"
	"time"

	"github.com/charmbracelet/log"

	"github.com/katzenpost/katzenpost/authority/voting/client"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
)

// Client manages startup, shutdow, creating new connections and reconnecting.
type Client struct {
	sync.RWMutex

	log        *log.Logger
	logbackend io.Writer

	// messagePollInterval is the interval at which the server will be
	// polled for new messages if the queue is believed to be empty.
	// XXX This will go away once we get rid of polling.
	messagePollInterval time.Duration

	pki *pki
	cfg *config.Config

	conn *connection

	sphinx *sphinx.Sphinx
	geo    *geo.Geometry

	haltedCh chan interface{}
	haltOnce sync.Once

	PKIClient cpki.Client
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
	c.log.Info("Starting graceful shutdown.")

	if c.conn != nil {
		c.conn.Halt()
		// nil out after the PKI is torn down due to a dependency.
	}

	if c.pki != nil {
		c.pki.Halt()
		c.pki = nil
	}
	c.conn = nil

	c.log.Info("Shutdown complete.")
	close(c.haltedCh)
}

// XXX This will go away once we get rid of polling.
func (c *Client) SetPollInterval(interval time.Duration) {
	c.Lock()
	c.messagePollInterval = interval
	c.Unlock()
}

// XXX This will go away once we get rid of polling.
func (c *Client) GetPollInterval() time.Duration {
	c.RLock()
	defer c.RUnlock()
	return c.messagePollInterval
}

func (c *Client) Start() error {
	c.log.Info("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")

	c.conn = newConnection(c)

	pkilinkKey, _ := wire.DefaultScheme.GenerateKeypair(rand.Reader)
	pkiClientConfig := &client.Config{
		LinkKey:       pkilinkKey,
		LogBackend:    c.logbackend,
		Authorities:   c.cfg.VotingAuthority.Peers,
		DialContextFn: nil,
	}
	var err error
	c.PKIClient, err = client.New(pkiClientConfig)
	if err != nil {
		return err
	}
	c.pki = newPKI(c)
	c.pki.start()
	c.conn.start()
	if c.cfg.CachedDocument != nil {
		// connectWorker waits for a pki fetch, we already have a document cached, so wake the worker
		c.conn.onPKIFetch()
	}
	return nil
}

// New creates a new Client with the provided configuration.
func New(cfg *config.Config, logbackend io.Writer) (*Client, error) {
	if err := cfg.FixupAndValidate(); err != nil {
		return nil, err
	}

	c := new(Client)
	c.logbackend = logbackend
	c.geo = cfg.SphinxGeometry
	var err error
	c.sphinx, err = sphinx.FromGeometry(cfg.SphinxGeometry)
	if err != nil {
		return nil, err
	}
	c.cfg = cfg
	c.log = log.NewWithOptions(logbackend, log.Options{
		ReportTimestamp: true,
		Prefix:          "client2",
	})

	c.haltedCh = make(chan interface{})

	return c, nil
}
