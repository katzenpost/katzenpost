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
	"path/filepath"
	"sync"
	"time"

	"github.com/beeker1121/goque"
	"github.com/katzenpost/client/config"
	"github.com/katzenpost/client/poisson"
	"github.com/katzenpost/core/crypto/ecdh"
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

	cfg *config.Config

	linkKey   *ecdh.PrivateKey
	pkiClient pki.Client
	minclient *minclient.Client

	logBackend *log.Backend
	log        *logging.Logger

	fatalErrCh chan error
	haltedCh   chan interface{}
	haltOnce   sync.Once

	pTimer *poisson.PoissonTimer // timer for legit messages and drop decoys
	dTimer *poisson.PoissonTimer // timer for drop decoys
	lTimer *poisson.PoissonTimer // optional timer for loop decoys

	opCh chan workerOp

	onlineAt       time.Time
	condGotPKIDoc  *sync.Cond
	hasPKIDoc      bool
	condGotMessage *sync.Cond
	condGotReply   *sync.Cond
	condGotConnect *sync.Cond
	egressQueue    *goque.Queue
	surbKeys       map[[sConstants.SURBIDLength]byte][]byte
	surbEtas       map[time.Duration][sConstants.SURBIDLength]byte
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

	c.log.Noticef("Shutdown complete.")
	close(c.haltedCh)
}

// New creates a new Client with the provided configuration.
func New(cfg *config.Config) (*Client, error) {
	c := new(Client)
	c.cfg = cfg
	c.fatalErrCh = make(chan error)
	c.haltedCh = make(chan interface{})
	c.opCh = make(chan workerOp)
	c.surbKeys = make(map[[sConstants.SURBIDLength]byte][]byte)
	c.surbEtas = make(map[time.Duration][sConstants.SURBIDLength]byte)

	const egressQueueName = "egress_queue"
	egressQueueDir := filepath.Join(c.cfg.Proxy.DataDir, egressQueueName)
	err := utils.MkDataDir(egressQueueDir)
	if err != nil {
		return nil, err
	}
	c.egressQueue, err = goque.OpenQueue(egressQueueDir)
	if err != nil {
		return nil, err
	}

	// make some synchronised conditions
	docLock := new(sync.Mutex)
	docLock.Lock()
	c.condGotPKIDoc = sync.NewCond(docLock)
	gotMsgLock := new(sync.Mutex)
	gotMsgLock.Lock()
	c.condGotMessage = sync.NewCond(gotMsgLock)
	gotReplyLock := new(sync.Mutex)
	gotReplyLock.Lock()
	c.condGotReply = sync.NewCond(gotReplyLock)
	gotConnectLock := new(sync.Mutex)
	gotConnectLock.Lock()
	c.condGotConnect = sync.NewCond(gotConnectLock)

	// Do the early initialization and bring up logging.
	if err := utils.MkDataDir(c.cfg.Proxy.DataDir); err != nil {
		return nil, err
	}
	if err := c.initLogging(); err != nil {
		return nil, err
	}

	// Load link key.
	id := fmt.Sprintf("%s@%s", c.cfg.Account.User, c.cfg.Account.Provider)
	basePath := filepath.Join(c.cfg.Proxy.DataDir, id)
	linkPriv := filepath.Join(basePath, "link.private.pem")
	linkPub := filepath.Join(basePath, "link.public.pem")
	if c.linkKey, err = ecdh.Load(linkPriv, linkPub, nil); err != nil {
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
