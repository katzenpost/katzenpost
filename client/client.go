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
	mrand "math/rand"
	"path/filepath"
	"sync"
	"time"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"gopkg.in/op/go-logging.v1"
)

const (
	initialPKIConsensusTimeout = 45 * time.Second
)

// NewEphemeralClient creates a new linkKey and associated account on a
// provider that suppports TrustOnFirstUse clients.
func NewEphemeralClient(cfg *config.Config) (*config.Config, *ecdh.PrivateKey, error) {
	// Retrieve a copy of the PKI consensus document.
	logFilePath := ""
	backendLog, err := log.New(logFilePath, "DEBUG", false)
	if err != nil {
		return nil, nil, err
	}
	proxyCfg := cfg.UpstreamProxyConfig()
	pkiClient, err := cfg.NewPKIClient(backendLog, proxyCfg)
	if err != nil {
		return nil, nil, err
	}
	currentEpoch, _, _ := epochtime.FromUnix(time.Now().Unix())
	ctx, cancel := context.WithTimeout(context.Background(), initialPKIConsensusTimeout)
	defer cancel()
	doc, _, err := pkiClient.Get(ctx, currentEpoch)
	if err != nil {
		return nil, nil, err
	}

	// Pick a Provider that supports TrustOnFirstUse and Ephemeral clients.
	providers := []*pki.MixDescriptor{}
	for _, provider := range doc.Providers {
		if provider.AuthenticationType == "Anonymous" {
			providers = append(providers, provider)
		}
	}
	if len(providers) == 0 {
		return nil, nil, errors.New("no Providers supporting ephemeral connections found in the consensus")
	}
	mrand.Seed(time.Now().UTC().UnixNano())
	provider := providers[mrand.Intn(len(providers))]

	fmt.Println("creating new linkKey for provider " + provider.Name)
	linkKey, err := ecdh.NewKeypair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	cfg.Account = &config.Account{
		User:           fmt.Sprintf("%x", linkKey.PublicKey().Bytes()),
		Provider:       provider.Name,
		ProviderKeyPin: provider.IdentityKey,
	}
	return cfg, linkKey, nil
}

// Client handles sending and receiving messages over the mix network
type Client struct {
	cfg        *config.Config
	logBackend *log.Backend
	log        *logging.Logger
	fatalErrCh chan error
	haltedCh   chan interface{}
	haltOnce   *sync.Once

	session *Session
}

func (c *Client) Provider() string {
	return c.cfg.Account.Provider
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

// Wait waits till the Client is terminated for any reason.
func (c *Client) Wait() {
	<-c.haltedCh
}

func (c *Client) halt() {
	c.log.Noticef("Starting graceful shutdown.")
	if c.session != nil {
		c.session.Shutdown()
	}
	close(c.fatalErrCh)
	close(c.haltedCh)
}

// NewSession creates and returns a new session or an error.
func (c *Client) NewSession(linkKey *ecdh.PrivateKey) (*Session, error) {
	var err error
	timeout := time.Duration(c.cfg.Debug.SessionDialTimeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c.session, err = NewSession(ctx, c.fatalErrCh, c.logBackend, c.cfg, linkKey)
	return c.session, err
}

// New creates a new Client with the provided configuration.
func New(cfg *config.Config) (*Client, error) {
	c := new(Client)
	c.cfg = cfg
	c.fatalErrCh = make(chan error)
	c.haltedCh = make(chan interface{})
	c.haltOnce = new(sync.Once)

	if err := c.initLogging(); err != nil {
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
