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
	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// Client manages startup, shutdow, creating new connections and reconnecting.
type Client struct {
	log        *log.Logger
	logbackend io.Writer

	cfg *config.Config

	conn *connection

	sphinx *sphinx.Sphinx
	geo    *geo.Geometry

	haltedCh chan interface{}
	haltOnce sync.Once

	PKIClient cpki.Client

	lock      *sync.RWMutex
	clockSkew int64
	docs      sync.Map
	wg        sync.WaitGroup
}

// ClockSkew returns the current best guess difference between the client's
// system clock and the network's global clock, rounded to the nearest second,
// as measured against the provider during the handshake process.  Calls to
// this routine should not be made until the first `ClientConfig.OnConnFn(true)`
// callback.
func (c *Client) ClockSkew() time.Duration {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return time.Duration(c.clockSkew) * time.Second
}

func (c *Client) skewedUnixTime() int64 {
	if !c.cfg.Debug.EnableTimeSync {
		return time.Now().Unix()
	}

	c.lock.RLock()
	defer c.lock.RUnlock()

	return time.Now().Unix() + c.clockSkew
}

func (c *Client) setClockSkew(skew int64) {
	c.log.Debugf("New clock skew: %v sec", skew)
	c.lock.Lock()
	c.clockSkew = skew
	c.lock.Unlock()
}

func (c *Client) CurrentDocument() *cpki.Document {
	now, _, _ := epochtime.FromUnix(c.skewedUnixTime())
	if d, _ := c.docs.Load(now); d != nil {
		return d.(*cpki.Document)
	}

	return nil
}

// XXX FIXME call c.wg.Done() from another thread!!!
func (c *Client) WaitForCurrentDocument() {
	if c.CurrentDocument() == nil {
		c.wg.Wait()
	}
	return
}

func (c *Client) receivedConsensus(consensus *commands.Consensus) {
	if consensus.ErrorCode != commands.ConsensusOk {
		c.log.Error("received consensus with error")
		return
	}
	doc, err := c.PKIClient.Deserialize(consensus.Payload)
	if err != nil {
		c.log.Error(err)
	}
	c.docs.Store(doc.Epoch, doc)

	if c.CurrentDocument() == nil {
		c.wg.Done()
	}
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

	c.conn = nil

	c.log.Info("Shutdown complete.")
	close(c.haltedCh)
}

func (c *Client) Start() error {
	c.log.Info("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")

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

	c.wg.Add(1)
	c.conn = newConnection(c)
	c.conn.start()
	return nil
}

// New creates a new Client with the provided configuration.
func New(cfg *config.Config, logbackend io.Writer) (*Client, error) {
	if err := cfg.FixupAndValidate(); err != nil {
		return nil, err
	}

	c := new(Client)
	c.lock = new(sync.RWMutex)
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
