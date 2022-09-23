// server.go - Katzenpost server.
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

// Package server provides the Katzenpost server.
package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gitlab.com/yawning/aez.git"
	"golang.org/x/crypto/blake2b"
	"gopkg.in/eapache/channels.v1"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/crypto/cert"
	"github.com/katzenpost/katzenpost/core/crypto/pem"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/crypto/sign"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/thwack"
	"github.com/katzenpost/katzenpost/core/utils"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/cryptoworker"
	"github.com/katzenpost/katzenpost/server/internal/decoy"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/incoming"
	"github.com/katzenpost/katzenpost/server/internal/instrument"
	"github.com/katzenpost/katzenpost/server/internal/outgoing"
	"github.com/katzenpost/katzenpost/server/internal/pki"
	"github.com/katzenpost/katzenpost/server/internal/provider"
	"github.com/katzenpost/katzenpost/server/internal/scheduler"
)

// ErrGenerateOnly is the error returned when the server initialization
// terminates due to the `GenerateOnly` debug config option.
var ErrGenerateOnly = errors.New("server: GenerateOnly set")

// Server is a Katzenpost server instance.
type Server struct {
	cfg *config.Config

	identityPrivateKey sign.PrivateKey
	identityPublicKey  sign.PublicKey
	linkKey            wire.PrivateKey

	logBackend *log.Backend
	log        *logging.Logger

	inboundPackets *channels.InfiniteChannel

	scheduler     glue.Scheduler
	cryptoWorkers []*cryptoworker.Worker
	periodic      *periodicTimer
	mixKeys       glue.MixKeys
	pki           glue.PKI
	listeners     []glue.Listener
	connector     glue.Connector
	provider      glue.Provider
	decoy         glue.Decoy
	management    *thwack.Server

	fatalErrCh chan error
	haltedCh   chan interface{}
	haltOnce   sync.Once
}

func (s *Server) initLogging() error {
	p := s.cfg.Logging.File
	if !s.cfg.Logging.Disable && s.cfg.Logging.File != "" {
		if !filepath.IsAbs(p) {
			p = filepath.Join(s.cfg.Server.DataDir, p)
		}
	}

	var err error
	s.logBackend, err = log.New(p, s.cfg.Logging.Level, s.cfg.Logging.Disable)
	if err == nil {
		s.log = s.logBackend.GetLogger("server")
	}
	return err
}

func (s *Server) reshadowCryptoWorkers() {
	s.log.Debugf("Calling all crypto workers to re-shadow the mix keys.")
	for _, w := range s.cryptoWorkers {
		w.UpdateMixKeys()
	}
}

// IdentityKey returns the running server's identity public key.
func (s *Server) IdentityKey() sign.PublicKey {
	return s.identityPublicKey
}

// RotateLog rotates the log file
// if logging to a file is enabled.
func (s *Server) RotateLog() {
	err := s.logBackend.Rotate()
	if err != nil {
		s.fatalErrCh <- fmt.Errorf("failed to rotate log file, shutting down server")
	}
}

// Shutdown cleanly shuts down a given Server instance.
func (s *Server) Shutdown() {
	s.haltOnce.Do(func() { s.halt() })
}

// Wait waits till the server is terminated for any reason.
func (s *Server) Wait() {
	<-s.haltedCh
}

func (s *Server) halt() {
	// WARNING: The ordering of operations here is deliberate, and should not
	// be altered without a deep understanding of how all the components fit
	// together.

	s.log.Noticef("Starting graceful shutdown.")

	// Stop the 1 Hz periodic utility timer.
	if s.periodic != nil {
		s.periodic.Halt()
		s.periodic = nil
	}

	// Stop the management interface.
	if s.management != nil {
		s.management.Halt()
		s.management = nil
	}

	// Stop the decoy source/sink.
	if s.decoy != nil {
		s.decoy.Halt()
		// Don't nil this out till after the PKI has been torn down.
	}

	// Stop the listener(s), close all incoming connections.
	for i, l := range s.listeners {
		if l != nil {
			l.Halt() // Closes all connections.
			s.listeners[i] = nil
		}
	}

	// Close all outgoing connections.
	if s.connector != nil {
		s.connector.Halt()
		// Don't nil this out till after the PKI has been torn down.
	}

	// Stop the Sphinx workers.
	for i, w := range s.cryptoWorkers {
		if w != nil {
			w.Halt()
			s.cryptoWorkers[i] = nil
		}
	}

	// Provider specific cleanup.
	if s.provider != nil {
		s.provider.Halt()
		s.provider = nil
	}

	// Stop the scheduler.
	if s.scheduler != nil {
		s.scheduler.Halt()
		s.scheduler = nil
	}

	// Stop the PKI interface.
	if s.pki != nil {
		s.pki.Halt()
		s.pki = nil

		// PKI calls into the connector/decoy.
		s.connector = nil
		s.decoy = nil
	}

	// Flush and close the mix keys.
	if s.mixKeys != nil {
		s.mixKeys.Halt()
		s.mixKeys = nil
	}

	// Clean up the top level components.
	if s.inboundPackets != nil {
		s.inboundPackets.Close()
	}
	s.linkKey.Reset()
	s.identityPrivateKey.Reset()
	s.identityPublicKey.Reset()
	close(s.fatalErrCh)

	s.log.Noticef("Shutdown complete.")
	close(s.haltedCh)
}

// New returns a new Server instance parameterized with the specified
// configuration.
func New(cfg *config.Config) (*Server, error) {
	s := &Server{
		cfg:        cfg,
		fatalErrCh: make(chan error),
		haltedCh:   make(chan interface{}),
	}
	goo := &serverGlue{s}

	// Do the early initialization and bring up logging.
	if err := utils.MkDataDir(s.cfg.Server.DataDir); err != nil {
		return nil, err
	}
	if err := s.initLogging(); err != nil {
		return nil, err
	}
	instrument.Init()

	s.log.Notice("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")
	if s.cfg.Logging.Level == "DEBUG" {
		s.log.Warning("Unsafe Debug logging is enabled.")
	}
	if aez.IsHardwareAccelerated() {
		s.log.Noticef("AEZv5 implementation is hardware accelerated.")
	} else {
		s.log.Warningf("AEZv5 implementation IS NOT hardware accelerated.")
	}
	s.log.Noticef("Server identifier is: '%v'", s.cfg.Server.Identifier)

	// Initialize the server identity and link keys.
	identityPrivateKeyFile := filepath.Join(s.cfg.Server.DataDir, "identity.private.pem")
	identityPublicKeyFile := filepath.Join(s.cfg.Server.DataDir, "identity.public.pem")

	s.identityPrivateKey, s.identityPublicKey = cert.Scheme.NewKeypair()

	if pem.BothExists(identityPrivateKeyFile, identityPublicKeyFile) {
		err := pem.FromFile(identityPrivateKeyFile, s.identityPrivateKey)
		if err != nil {
			return nil, err
		}
		err = pem.FromFile(identityPublicKeyFile, s.identityPublicKey)
		if err != nil {
			return nil, err
		}
	} else if pem.BothNotExists(identityPrivateKeyFile, identityPublicKeyFile) {
		err := pem.ToFile(identityPrivateKeyFile, s.identityPrivateKey)
		if err != nil {
			return nil, err
		}
		err = pem.ToFile(identityPublicKeyFile, s.identityPublicKey)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("%s and %s must either both exist or not exist", identityPrivateKeyFile, identityPublicKeyFile)
	}

	var err error
	idPubKeyHash := s.identityPublicKey.Sum256()
	s.log.Noticef("Server identity public key is: %x", idPubKeyHash[:])
	linkKeyFile := filepath.Join(s.cfg.Server.DataDir, "link.private.pem")
	scheme := wire.NewScheme()
	if s.linkKey, err = scheme.Load(linkKeyFile, "", rand.Reader); err != nil {
		s.log.Errorf("Failed to initialize link key: %v", err)
		return nil, err
	}
	linkPubKeyHash := blake2b.Sum256(s.linkKey.PublicKey().Bytes())
	s.log.Noticef("Server link public key is: %x", linkPubKeyHash[:])

	if s.cfg.Debug.GenerateOnly {
		return nil, ErrGenerateOnly
	}

	// Load and or generate mix keys.
	if s.mixKeys, err = newMixKeys(goo); err != nil {
		s.log.Errorf("Failed to initialize mix keys: %v", err)
		return nil, err
	}

	// Past this point, failures need to call s.Shutdown() to do cleanup.
	isOk := false
	defer func() {
		// Something failed in bringing the server up, past the point where
		// files are open etc, clean up the partially constructed instance.
		if !isOk {
			s.Shutdown()
		}
	}()

	// Start the fatal error watcher.
	go func() {
		err, ok := <-s.fatalErrCh
		if !ok {
			// Graceful termination.
			return
		}
		s.log.Warningf("Shutting down due to error: %v", err)
		s.Shutdown()
	}()

	// Initialize the management interface if enabled.
	//
	// Note: This is done first so that other subsystems may register commands.
	if _, err := os.Stat(s.cfg.Management.Path); !os.IsNotExist(err) {
		s.log.Warningf("Warning: management socket file '%s' already exists, deleting it.", s.cfg.Management.Path)
		err := os.Remove(s.cfg.Management.Path)
		if err != nil {
			s.fatalErrCh <- fmt.Errorf("failed to delete mgmt socket file, shutting down now")
			return nil, err
		}
	}
	if s.cfg.Management.Enable {
		mgmtCfg := &thwack.Config{
			Net:         "unix",
			Addr:        s.cfg.Management.Path,
			ServiceName: s.cfg.Server.Identifier + " Katzenpost Management Interface",
			LogModule:   "mgmt",
			NewLoggerFn: s.logBackend.GetLogger,
		}
		if s.management, err = thwack.New(mgmtCfg); err != nil {
			s.log.Errorf("Failed to initialize management interface: %v", err)
			return nil, err
		}

		const shutdownCmd = "SHUTDOWN"
		s.management.RegisterCommand(shutdownCmd, func(c *thwack.Conn, l string) error {
			s.fatalErrCh <- fmt.Errorf("user requested shutdown via mgmt interface")
			return nil
		})
	}

	// Initialize the PKI interface.
	if s.pki, err = pki.New(goo); err != nil {
		s.log.Errorf("Failed to initialize PKI client: %v", err)
		return nil, err
	}

	// Initialize the provider backend.
	if s.cfg.Server.IsProvider {
		if s.provider, err = provider.New(goo); err != nil {
			s.log.Errorf("Failed to initialize provider backend: %v", err)
			return nil, err
		}
	}

	// Initialize and start the the scheduler.
	if s.scheduler, err = scheduler.New(goo); err != nil {
		s.log.Errorf("Failed to initialize scheduler: %v", err)
		return nil, err
	}

	// Initialize and start the Sphinx workers.
	s.inboundPackets = channels.NewInfiniteChannel()
	s.cryptoWorkers = make([]*cryptoworker.Worker, 0, s.cfg.Debug.NumSphinxWorkers)
	for i := 0; i < s.cfg.Debug.NumSphinxWorkers; i++ {
		w := cryptoworker.New(goo, s.inboundPackets.Out(), i)
		s.cryptoWorkers = append(s.cryptoWorkers, w)
	}

	// Initialize the outgoing connection manager, decoy source/sink, and then
	// start the PKI worker.
	s.connector = outgoing.New(goo)
	if s.decoy, err = decoy.New(goo); err != nil {
		s.log.Errorf("Failed to initialize decoy source/sink: %v", err)
		return nil, err
	}

	// Bring the listener(s) online.
	s.listeners = make([]glue.Listener, 0, len(s.cfg.Server.Addresses))
	for i, addr := range s.cfg.Server.Addresses {
		l, err := incoming.New(goo, s.inboundPackets.In(), i, addr)
		if err != nil {
			s.log.Errorf("Failed to spawn listener on address: %v (%v).", addr, err)
			return nil, err
		}
		s.listeners = append(s.listeners, l)
	}

	s.pki.StartWorker()

	// Start the periodic 1 Hz utility timer.
	s.periodic = newPeriodicTimer(s)

	// Start listening on the management interface if enabled, now that every
	// subsystem that wants to register commands has had the opportunity to do
	// so.
	if s.management != nil {
		s.management.Start()
	}

	isOk = true
	return s, nil
}

type serverGlue struct {
	s *Server
}

func (g *serverGlue) Config() *config.Config {
	return g.s.cfg
}

func (g *serverGlue) LogBackend() *log.Backend {
	return g.s.logBackend
}

func (g *serverGlue) IdentityKey() sign.PrivateKey {
	return g.s.identityPrivateKey
}

func (g *serverGlue) IdentityPublicKey() sign.PublicKey {
	return g.s.identityPublicKey
}

func (g *serverGlue) LinkKey() wire.PrivateKey {
	return g.s.linkKey
}

func (g *serverGlue) Management() *thwack.Server {
	return g.s.management
}

func (g *serverGlue) MixKeys() glue.MixKeys {
	return g.s.mixKeys
}

func (g *serverGlue) PKI() glue.PKI {
	return g.s.pki
}

func (g *serverGlue) Provider() glue.Provider {
	return g.s.provider
}

func (g *serverGlue) Scheduler() glue.Scheduler {
	return g.s.scheduler
}

func (g *serverGlue) Connector() glue.Connector {
	return g.s.connector
}

func (g *serverGlue) Listeners() []glue.Listener {
	return g.s.listeners
}

func (g *serverGlue) Decoy() glue.Decoy {
	return g.s.decoy
}

func (g *serverGlue) ReshadowCryptoWorkers() {
	g.s.reshadowCryptoWorkers()
}
