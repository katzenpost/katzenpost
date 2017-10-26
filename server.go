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
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"git.schwanenlied.me/yawning/aez.git"
	"github.com/eapache/channels"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/thwack"
	"github.com/katzenpost/server/config"
	"github.com/op/go-logging"
)

// ErrGenerateOnly is the error returned when the server initialization
// terminates due to the `GenerateOnly` debug config option.
var ErrGenerateOnly = errors.New("server: GenerateOnly set")

// Server is a Katzenpost server instance.
type Server struct {
	cfg *config.Config

	identityKey *eddsa.PrivateKey
	linkKey     *ecdh.PrivateKey

	logBackend *log.Backend
	log        *logging.Logger

	inboundPackets *channels.InfiniteChannel

	scheduler     *scheduler
	cryptoWorkers []*cryptoWorker
	periodic      *periodicTimer
	mixKeys       *mixKeys
	pki           *pki
	listeners     []*listener
	connector     *connector
	provider      *provider
	management    *thwack.Server

	fatalErrCh chan error
	haltedCh   chan interface{}
	haltOnce   sync.Once
}

func (s *Server) initDataDir() error {
	const dirMode = os.ModeDir | 0700
	d := s.cfg.Server.DataDir

	// Initialize the data directory, by ensuring that it exists (or can be
	// created), and that it has the appropriate permissions.
	if fi, err := os.Lstat(d); err != nil {
		// Directory doesn't exist, create one.
		if !os.IsNotExist(err) {
			return fmt.Errorf("server: failed to stat() DataDir: %v", err)
		}
		if err = os.Mkdir(d, dirMode); err != nil {
			return fmt.Errorf("server: failed to create DataDir: %v", err)
		}
	} else {
		if !fi.IsDir() {
			return fmt.Errorf("server: DataDir '%v' is not a directory", d)
		}
		if fi.Mode() != dirMode {
			return fmt.Errorf("server: DataDir '%v' has invalid permissions '%v'", d, fi.Mode())
		}
	}

	return nil
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
		w.updateMixKeys()
	}
}

// IdentityKey returns the running server's identity public key.
func (s *Server) IdentityKey() *eddsa.PublicKey {
	return s.identityKey.PublicKey()
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
		s.periodic.halt()
		s.periodic = nil
	}

	// Stop the management interface.
	if s.management != nil {
		s.management.Halt()
		s.management = nil
	}

	// Stop the listener(s), close all incoming connections.
	for i, l := range s.listeners {
		if l != nil {
			l.halt() // Closes all connections.
			s.listeners[i] = nil
		}
	}

	// Close all outgoing connections.
	if s.connector != nil {
		s.connector.halt()
		// Don't nil this out till after the PKI has been torn down.
	}

	// Stop the Sphinx workers.
	for i, w := range s.cryptoWorkers {
		if w != nil {
			w.halt()
			s.cryptoWorkers[i] = nil
		}
	}

	// Provider specific cleanup.
	if s.provider != nil {
		s.provider.halt()
		s.provider = nil
	}

	// Stop the scheduler.
	if s.scheduler != nil {
		s.scheduler.halt()
		s.scheduler = nil
	}

	// Stop the PKI interface.
	if s.pki != nil {
		s.pki.halt()
		s.pki = nil
		s.connector = nil // PKI calls into the connector.
	}

	// Flush and close the mix keys.
	if s.mixKeys != nil {
		s.mixKeys.halt()
		s.mixKeys = nil
	}

	// Clean up the top level components.
	if s.inboundPackets != nil {
		s.inboundPackets.Close()
	}
	s.linkKey.Reset()
	s.identityKey.Reset()
	close(s.fatalErrCh)

	s.log.Noticef("Shutdown complete.")
	close(s.haltedCh)
}

// New returns a new Server instance parameterized with the specified
// configuration.
func New(cfg *config.Config) (*Server, error) {
	s := new(Server)
	s.cfg = cfg
	s.fatalErrCh = make(chan error)
	s.haltedCh = make(chan interface{})

	// Do the early initialization and bring up logging.
	if err := s.initDataDir(); err != nil {
		return nil, err
	}
	if err := s.initLogging(); err != nil {
		return nil, err
	}

	s.log.Notice("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")
	if s.cfg.Debug.IsUnsafe() {
		s.log.Warning("Unsafe Debug configuration options are set.")
	}
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
	var err error
	if s.cfg.Debug.ForceIdentityKey != "" {
		s.log.Warning("ForceIdentityKey should NOT be used for production deployments.")
		keyStr := strings.TrimSpace(s.cfg.Debug.ForceIdentityKey)
		raw, err := hex.DecodeString(keyStr)
		if err != nil {
			s.log.Errorf("Failed to parse forced identity: %v", err)
			return nil, err
		}
		s.identityKey = new(eddsa.PrivateKey)
		if err = s.identityKey.FromBytes(raw); err != nil {
			s.log.Errorf("Failed to initialize identity: %v", err)
			return nil, err
		}
	} else {
		identityPrivateKeyFile := filepath.Join(s.cfg.Server.DataDir, "identity.private.pem")
		identityPublicKeyFile := filepath.Join(s.cfg.Server.DataDir, "identity.public.pem")
		if s.identityKey, err = eddsa.Load(identityPrivateKeyFile, identityPublicKeyFile, rand.Reader); err != nil {
			s.log.Errorf("Failed to initialize identity: %v", err)
			return nil, err
		}
	}
	s.log.Noticef("Server identity public key is: %s", s.identityKey.PublicKey())
	linkKeyFile := filepath.Join(s.cfg.Server.DataDir, "link.private.pem")
	if s.linkKey, err = ecdh.Load(linkKeyFile, rand.Reader); err != nil {
		s.log.Errorf("Failed to initialize link key: %v", err)
		return nil, err
	}
	s.log.Noticef("Server link public key is: %s", s.linkKey.PublicKey())

	if s.cfg.Debug.GenerateOnly {
		return nil, ErrGenerateOnly
	}

	// Load and or generate mix keys.
	if s.mixKeys, err = newMixKeys(s); err != nil {
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
	if s.pki, err = newPKI(s); err != nil {
		s.log.Errorf("Failed to initialize PKI client: %v", err)
		return nil, err
	}

	// Initialize the provider backend.
	if s.cfg.Server.IsProvider {
		if s.provider, err = newProvider(s); err != nil {
			s.log.Errorf("Failed to initialize provider backend: %v", err)
			return nil, err
		}
	}

	// Initialize and start the the scheduler.
	s.scheduler = newScheduler(s)

	// Initialize and start the Sphinx workers.
	s.inboundPackets = channels.NewInfiniteChannel()
	s.cryptoWorkers = make([]*cryptoWorker, 0, s.cfg.Debug.NumSphinxWorkers)
	for i := 0; i < s.cfg.Debug.NumSphinxWorkers; i++ {
		w := newCryptoWorker(s, i)
		s.cryptoWorkers = append(s.cryptoWorkers, w)
	}

	// Initialize the outgoing connection manager, and then start the PKI
	// worker.
	s.connector = newConnector(s)
	s.pki.startWorker()

	// Bring the listener(s) online.
	s.listeners = make([]*listener, 0, len(s.cfg.Server.Addresses))
	for i, addr := range s.cfg.Server.Addresses {
		l, err := newListener(s, i, addr)
		if err != nil {
			s.log.Errorf("Failed to spawn listener on address: %v (%v).", addr, err)
			return nil, err
		}
		s.listeners = append(s.listeners, l)
	}

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
