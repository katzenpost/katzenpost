// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/authority/voting/client"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/worker"
)

// Client manages startup, shutdow, creating new connections and reconnecting.
type Client struct {
	worker.Worker
	sync.RWMutex

	log        *logging.Logger
	logbackend *log.Backend

	// messagePollInterval is the interval at which the server will be
	// polled for new messages if the queue is believed to be empty.
	// XXX This will go away once we get rid of polling.
	messagePollInterval time.Duration

	pki *pki
	cfg *config.Config

	conn *connection

	sphinx        *sphinx.Sphinx
	geo           *geo.Geometry
	wireKEMScheme kem.Scheme

	PKIClient cpki.Client

	// DialContextFn is the optional alternative Dialer.DialContext function
	// to be used when creating outgoing network connections.
	DialContextFn func(ctx context.Context, network, address string) (net.Conn, error)
}

// Shutdown cleanly shuts down a given Client instance.
func (c *Client) Shutdown() {
	shutdownStart := time.Now()
	c.log.Info("Starting graceful client shutdown.")

	if c.conn != nil {
		connStart := time.Now()
		c.log.Debug("Stopping connection")
		c.conn.Shutdown()
		c.log.Debugf("Connection stopped in %v", time.Since(connStart))
	}

	// Parallelize PKI and main client shutdown for faster cleanup
	var clientShutdownWg sync.WaitGroup
	clientShutdownWg.Add(2)

	go func() {
		defer clientShutdownWg.Done()
		if c.pki != nil {
			start := time.Now()
			c.log.Debug("Stopping PKI worker")
			c.pki.Halt()
			c.log.Debugf("PKI worker stopped in %v", time.Since(start))
		}
	}()

	go func() {
		defer clientShutdownWg.Done()
		start := time.Now()
		c.log.Debug("Stopping main client worker")
		c.Halt()
		c.log.Debugf("Main client worker stopped in %v", time.Since(start))
	}()

	clientShutdownWg.Wait()
	c.log.Infof("Client shutdown complete in %v", time.Since(shutdownStart))
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

	_, pkilinkKey, err := c.wireKEMScheme.GenerateKeyPair()
	if err != nil {
		return err
	}
	pkiClientConfig := &client.Config{
		LinkKey:       pkilinkKey,
		LogBackend:    c.logbackend,
		Authorities:   c.cfg.VotingAuthority.Peers,
		DialContextFn: nil,
	}
	c.PKIClient, err = client.New(pkiClientConfig)
	if err != nil {
		return err
	}
	c.pki = newPKI(c)
	c.pki.start()
	c.conn.start()
	return nil
}

// New creates a new Client with the provided configuration.
func New(cfg *config.Config, logBackend *log.Backend) (*Client, error) {
	if err := cfg.FixupAndValidate(); err != nil {
		return nil, err
	}

	c := new(Client)
	c.logbackend = logBackend
	c.wireKEMScheme = schemes.ByName(cfg.WireKEMScheme)
	c.geo = cfg.SphinxGeometry
	var err error
	c.sphinx, err = sphinx.FromGeometry(cfg.SphinxGeometry)
	if err != nil {
		return nil, err
	}
	c.cfg = cfg

	// A per-connection tag (for Tor SOCKS5 stream isloation)
	proxyContext := fmt.Sprintf("session %d", rand.NewMath().Uint64())
	dialFn := cfg.UpstreamProxyConfig().ToDialContext(proxyContext)
	if dialFn == nil {
		dialFn = defaultDialer.DialContext
	}
	c.DialContextFn = dialFn

	c.log = c.logbackend.GetLogger("katzenpost/client2")

	return c, nil
}
