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
	"path/filepath"
	"sync"
	"time"

	"github.com/katzenpost/client/config"
	cConstants "github.com/katzenpost/client/constants"
	"github.com/katzenpost/client/poisson"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/pki"
	sConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/utils"
	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/minclient"
	"gopkg.in/op/go-logging.v1"
)

// Client handles sending and receiving messages over the mix network
type Client struct {
	worker.Worker

	cfg        *config.Config
	linkKey    *ecdh.PrivateKey
	pkiClient  pki.Client
	minclient  *minclient.Client
	logBackend *log.Backend
	log        *logging.Logger
	fatalErrCh chan error
	haltedCh   chan interface{}
	haltOnce   sync.Once

	pTimer *poisson.PoissonTimer // timer for legit messages and drop decoys
	dTimer *poisson.PoissonTimer // timer for drop decoys
	lTimer *poisson.PoissonTimer // optional timer for loop decoys

	opCh        chan workerOp
	onlineAt    time.Time
	hasPKIDoc   bool
	egressQueue EgressQueue
	surbKeys    map[[sConstants.SURBIDLength]byte][]byte
	surbEtas    map[time.Duration][sConstants.SURBIDLength]byte

	condGotPKIDoc  *sync.Cond
	condGotConnect *sync.Cond

	surbIDMap      map[[sConstants.SURBIDLength]byte]*MessageRef
	messageIDMap   map[[cConstants.MessageIDLength]byte]*MessageRef
	replyNotifyMap map[[cConstants.MessageIDLength]byte]*sync.Mutex
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
		c.log = c.logBackend.GetLogger("katzenpost/client")
	}
	return err
}

func (c *Client) GetLogger(name string) *logging.Logger {
	return c.logBackend.GetLogger(name)
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
	if c.minclient != nil {
		c.minclient.Shutdown()
	}
	c.Halt()
	close(c.fatalErrCh)
	close(c.haltedCh)
}

// New creates a new Client with the provided configuration.
func New(cfg *config.Config) (*Client, error) {
	c := new(Client)
	c.cfg = cfg
	c.fatalErrCh = make(chan error)
	c.haltedCh = make(chan interface{})
	c.opCh = make(chan workerOp)
	c.surbIDMap = make(map[[sConstants.SURBIDLength]byte]*MessageRef)
	c.messageIDMap = make(map[[cConstants.MessageIDLength]byte]*MessageRef)
	c.replyNotifyMap = make(map[[cConstants.MessageIDLength]byte]*sync.Mutex)
	c.egressQueue = new(Queue)

	// make some synchronised conditions
	c.condGotPKIDoc = sync.NewCond(new(sync.Mutex))
	c.condGotConnect = sync.NewCond(new(sync.Mutex))

	// Do the early initialization and bring up logging.
	if err := utils.MkDataDir(c.cfg.Proxy.DataDir); err != nil {
		return nil, err
	}
	if err := c.initLogging(); err != nil {
		return nil, err
	}

	// Load link key.
	basePath := c.cfg.Proxy.DataDir
	linkPriv := filepath.Join(basePath, "link.private.pem")
	linkPub := filepath.Join(basePath, "link.public.pem")
	var err error
	if c.linkKey, err = ecdh.Load(linkPriv, linkPub, rand.Reader); err != nil {
		c.log.Errorf("Failure to load link keys: %s", err)
		return nil, err
	}

	c.log.Noticef("😼 Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY. 😼")

	// Start the fatal error watcher.
	go func() {
		err, ok := <-c.fatalErrCh
		if !ok {
			return
		}
		c.log.Warningf("Shutting down due to error: %v", err)
		c.Shutdown()
	}()
	return c, nil
}
