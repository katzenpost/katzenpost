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
	"context"
	"fmt"
	mRand "math/rand"
	"net"
	"sync"
	"time"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/crypto/sign"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/wire"
	"gopkg.in/op/go-logging.v1"
)

// ClientConfig is a client configuration.
type ClientConfig struct {
	// User is the user identifier used to connect to the Provider.
	User string

	// Provider is the provider identifier to connect to.
	Provider string

	// ProviderKeyPin is the optional pinned provider signing key.
	// If specified, the client will refuse to accept provider descriptors
	// in PKI documents unless they are signed by the pinned key.
	ProviderKeyPin sign.PublicKey

	// LinkKey is the user's ECDH link authentication private key.
	LinkKey wire.PrivateKey

	// LogBackend is the logging backend to use for client logging.
	LogBackend *log.Backend

	// PKIClient is the PKI Document data source.
	PKIClient cpki.Client

	// OnConnFn is the callback function that will be called when the
	// connection status changes.  The error parameter will be nil on
	// successful connection establishment, otherwise it will be set
	// with the reason why a connection has been torn down (or a connect
	// attempt has failed).
	OnConnFn func(error)

	// OnMessageEmptyFn is the callback function that will be called
	// when the user's server side spool is empty.  This can happen
	// as the result of periodic background fetches.  Calls to the callback
	// that return an error will be treated as a signal to tear down the
	// connection.
	OnEmptyFn func() error

	// OnMessageFn is the callback function that will be called when
	// a message is retrived from the user's server side spool.  Callers
	// MUST be prepared to receive multiple callbacks with the same
	// message body.  Calls to the callback that return an error will
	// be treated as a signal to tear down the connection.
	OnMessageFn func([]byte) error

	// OnACKFn is the callback function that will be called when a
	// message CK is retreived from the user's server side spool.  Callers
	// MUST be prepared to receive multiple callbacks with the same
	// SURB ID and SURB ciphertext.  Calls to the callback that return
	// an error will be treated as a signal to tear down the connection.
	OnACKFn func(*[constants.SURBIDLength]byte, []byte) error

	// OnDocumentFn is the callback function taht will be called when a
	// new directory document is retreived for the current epoch.
	OnDocumentFn func(*cpki.Document)

	// DialContextFn is the optional alternative Dialer.DialContext function
	// to be used when creating outgoing network connections.
	DialContextFn func(ctx context.Context, network, address string) (net.Conn, error)

	// PreferedTransports is a list of the transports will be used to make
	// outgoing network connections, with the most prefered first.
	PreferedTransports []cpki.Transport

	// MessagePollInterval is the interval at which the server will be
	// polled for new messages if the queue is belived to be empty.
	// If left unset, an interval of 1 minute will be used.
	MessagePollInterval time.Duration

	// EnableTimeSync enables the use of skewed remote provider time
	// instead of system time when available.
	EnableTimeSync bool
}

func (cfg *ClientConfig) validate() error {
	if cfg.User == "" || len(cfg.User) > wire.MaxAdditionalDataLength {
		return fmt.Errorf("minclient: invalid User: '%v'", cfg.User)
	}
	if cfg.Provider == "" {
		return fmt.Errorf("minclient: invalid Provider: '%v'", cfg.Provider)
	}
	if cfg.LinkKey == nil {
		return fmt.Errorf("minclient: no LinkKey provided")
	}
	if cfg.LogBackend == nil {
		return fmt.Errorf("minclient: no LogBackend provided")
	}
	if cfg.PKIClient == nil {
		return fmt.Errorf("minclient: no PKIClient provided")
	}
	return nil
}

func (c *Client) SetPollInterval(interval time.Duration) {
	c.Lock()
	c.cfg.MessagePollInterval = interval
	c.Unlock()
}

func (c *Client) GetPollInterval() time.Duration {
	c.RLock()
	defer c.RUnlock()
	return c.cfg.MessagePollInterval
}

// Client is a client instance.
type Client struct {
	sync.RWMutex
	cfg *ClientConfig
	log *logging.Logger

	geo    *sphinx.Geometry
	sphinx *sphinx.Sphinx

	rng  *mRand.Rand
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

	c.log.Notice("Shutdown complete.")
	close(c.haltedCh)
}

// New creates a new Client with the provided configuration.
func New(cfg *ClientConfig) (*Client, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	c := new(Client)
	c.geo = sphinx.DefaultGeometry()
	c.sphinx = sphinx.DefaultSphinx()
	c.cfg = cfg
	c.displayName = fmt.Sprintf("%v@%v", c.cfg.User, c.cfg.Provider)
	c.log = cfg.LogBackend.GetLogger("minclient:" + c.displayName)
	c.haltedCh = make(chan interface{})

	c.log.Notice("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")
	c.log.Debugf("User/Provider is: %v", c.displayName)
	c.log.Debugf("User Link Key is: %v", c.cfg.LinkKey.PublicKey())

	c.rng = rand.NewMath()

	c.conn = newConnection(c)
	c.pki = newPKI(c)
	c.pki.start()
	c.conn.start()

	return c, nil
}
