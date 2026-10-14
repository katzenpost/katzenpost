// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"fmt"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/client"
	vServerConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/quic/common"
)

// Client manages startup, shutdow, creating new connections and reconnecting.
type Client struct {
	worker.Worker
	sync.RWMutex

	log        *logging.Logger
	logbackend *log.Backend

	pki *pki
	cfg *config.Config

	conn *connection

	preferredTransports atomic.Pointer[[]string]
	quicPinMismatches   common.QUICPinMismatches

	sphinx           *sphinx.Sphinx
	geo              *geo.Geometry
	wireKEMScheme    kem.Scheme
	maxConsensusSize int

	PKIClient cpki.Deserializer

	// DialContextFn is the optional alternative Dialer.DialContext function
	// to be used when creating outgoing network connections.
	DialContextFn func(ctx context.Context, network, address string) (net.Conn, error)
}

var defaultTransports = slices.DeleteFunc(slices.Clone(cpki.ClientTransports), func(t string) bool { return t == cpki.TransportQUIC })

func (c *Client) PreferredTransports() []string {
	if p := c.preferredTransports.Load(); p != nil {
		return *p
	}
	if c.cfg.PreferedTransports != nil {
		return c.cfg.PreferedTransports
	}
	return defaultTransports
}

func (c *Client) votingAuthorities() []*vServerConfig.Authority {
	if slices.Contains(c.cfg.PreferedTransports, cpki.TransportQUIC) {
		return c.cfg.VotingAuthority.Peers
	}
	peers := make([]*vServerConfig.Authority, 0, len(c.cfg.VotingAuthority.Peers))
	for _, peer := range c.cfg.VotingAuthority.Peers {
		withoutQUIC := *peer
		withoutQUIC.Addresses = slices.DeleteFunc(slices.Clone(peer.Addresses), common.IsQUICAddress)
		peers = append(peers, &withoutQUIC)
	}
	return peers
}

func (c *Client) SetPreferredTransports(transports []string) error {
	for i, t := range transports {
		if !slices.Contains(cpki.ClientTransports, t) {
			return fmt.Errorf("client: transport %q is not one of %v", t, cpki.ClientTransports)
		}
		if slices.Contains(transports[:i], t) {
			return fmt.Errorf("client: transport %q repeats", t)
		}
	}
	if len(transports) == 0 {
		c.preferredTransports.Store(nil)
		return nil
	}
	order := slices.Clone(transports)
	c.preferredTransports.Store(&order)
	return nil
}

func (c *Client) haltConnection() {
	if c.conn != nil {
		c.conn.isShutdown.Store(true)
		c.conn.Halt()
	}
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
		c.RLock()
		pki := c.pki
		c.RUnlock()
		if pki != nil {
			start := time.Now()
			c.log.Debug("Stopping PKI worker")
			pki.Halt()
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

func (c *Client) Start() error {
	// The pre-alpha banner is emitted once at daemon startup
	// (see Daemon logging setup); avoid logging it a second time here.
	c.conn = newConnection(c)

	_, pkilinkKey, err := c.wireKEMScheme.GenerateKeyPair()
	if err != nil {
		return err
	}
	pkiClientConfig := &client.Config{
		KEMScheme:          c.wireKEMScheme,
		PKISignatureScheme: signSchemes.ByName(c.cfg.PKISignatureScheme),
		LinkKey:            pkilinkKey,
		LogBackend:         c.logbackend,
		Authorities:        c.votingAuthorities(),
		Geo:                c.cfg.SphinxGeometry,
		DialContextFn:      c.DialContextFn,
		QUIC:               c.cfg.QUIC.ForClient(),

		MaxConsensusSize:        c.cfg.VotingAuthority.MaxConsensusSize,
		MaxConsensusSizeSetting: "VotingAuthority.MaxConsensusSize",
	}
	c.PKIClient, err = client.New(pkiClientConfig)
	if err != nil {
		return err
	}
	c.maxConsensusSize = pkiClientConfig.MaxConsensusSize
	c.Lock()
	c.pki = newPKI(c)
	c.Unlock()
	c.pki.start()
	c.conn.start()
	return nil
}

// New creates a new Client with the provided configuration.
func New(cfg *config.Config, logBackend *log.Backend) (*Client, error) {
	if err := cfg.FixupAndValidate(); err != nil {
		return nil, err
	}
	if err := epochtime.Configure(cfg.EpochDuration, os.Stderr); err != nil {
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
	c.DialContextFn = cfg.UpstreamProxyConfig().ToDialContext(proxyContext)

	c.log = c.logbackend.GetLogger("katzenpost/client")

	return c, nil
}
