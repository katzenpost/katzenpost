// server.go - Katzenpost non-voting authority server.
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

// Package server implements the Katzenpost non-voting authority server.
//
// The non-voting authority server is intended to be a stop gap for debugging
// and testing and is likely only suitable for very small networks where the
// lack of distributed trust and or quality of life features is a non-issue.
package server

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/katzenpost/authority/nonvoting/server/config"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/log"
	"gopkg.in/op/go-logging.v1"
)

// ErrGenerateOnly is the error returned when the server initialization
// terminates due to the `GenerateOnly` debug config option.
var ErrGenerateOnly = errors.New("server: GenerateOnly set")

// Server is a non-voting authority server instance.
type Server struct {
	sync.WaitGroup

	cfg *config.Config

	identityKey *eddsa.PrivateKey
	linkKey     *ecdh.PrivateKey

	logBackend *log.Backend
	log        *logging.Logger

	state     *state
	listeners []net.Listener

	fatalErrCh chan error
	haltedCh   chan interface{}
	haltOnce   sync.Once
}

func (s *Server) initDataDir() error {
	const dirMode = os.ModeDir | 0700
	d := s.cfg.Authority.DataDir

	// Initialize the data directory, by ensuring that it exists (or can be
	// created), and that it has the appropriate permissions.
	if fi, err := os.Lstat(d); err != nil {
		// Directory doesn't exist, create one.
		if !os.IsNotExist(err) {
			return fmt.Errorf("authority: failed to stat() DataDir: %v", err)
		}
		if err = os.Mkdir(d, dirMode); err != nil {
			return fmt.Errorf("authority: failed to create DataDir: %v", err)
		}
	} else {
		if !fi.IsDir() {
			return fmt.Errorf("authority: DataDir '%v' is not a directory", d)
		}
		if fi.Mode() != dirMode {
			return fmt.Errorf("authority: DataDir '%v' has invalid permissions '%v', should be '%v'", d, fi.Mode(), dirMode)
		}
	}

	return nil
}

func (s *Server) initLogging() error {
	p := s.cfg.Logging.File
	if !s.cfg.Logging.Disable && s.cfg.Logging.File != "" {
		if !filepath.IsAbs(p) {
			p = filepath.Join(s.cfg.Authority.DataDir, p)
		}
	}

	var err error
	s.logBackend, err = log.New(p, s.cfg.Logging.Level, s.cfg.Logging.Disable)
	if err == nil {
		s.log = s.logBackend.GetLogger("authority")
	}
	return err
}

// IdentityKey returns the running Server's identity public key.
func (s *Server) IdentityKey() *eddsa.PublicKey {
	return s.identityKey.PublicKey()
}

// RotateLog rotates the log file
// if logging to a file is enabled.
func (s *Server) RotateLog() {
	err := s.logBackend.Rotate()
	if err != nil {
		s.fatalErrCh <- fmt.Errorf("failed to rotate log file, shutting down server")
	}
	s.log.Notice("Log rotated.")
}

// Wait waits till the server is terminated for any reason.
func (s *Server) Wait() {
	<-s.haltedCh
}

// Shutdown cleanly shuts down a given Server instance.
func (s *Server) Shutdown() {
	s.haltOnce.Do(func() { s.halt() })
}

func (s *Server) listenWorker(l net.Listener) {
	addr := l.Addr()
	s.log.Noticef("Listening on: %v", addr)
	defer func() {
		s.log.Noticef("Stopping listening on: %v", addr)
		l.Close()
		s.Done()
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				s.log.Errorf("Critical accept failure: %v", err)
				return
			}
			continue
		}

		s.Add(1)
		s.onConn(conn)
	}

	// NOTREACHED
}

func (s *Server) halt() {
	s.log.Notice("Starting graceful shutdown.")

	// Halt the listeners.
	for idx, l := range s.listeners {
		if l != nil {
			l.Close()
		}
		s.listeners[idx] = nil
	}

	// Wait for all the connections to terminate.
	s.WaitGroup.Wait()

	// Halt the state worker.
	if s.state != nil {
		s.state.Halt()
		s.state = nil
	}

	s.identityKey.Reset()
	s.linkKey.Reset()
	close(s.fatalErrCh)

	s.log.Notice("Shutdown complete.")
	close(s.haltedCh)
}

// New returns a new Server instance parameterized with the specific
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
	if s.cfg.Logging.Level == "DEBUG" {
		s.log.Warning("Unsafe Debug logging is enabled.")
	}

	// Initialize the authority identity key.
	var err error
	if s.cfg.Debug.IdentityKey != nil {
		s.log.Warning("IdentityKey should NOT be used for production deployments.")
		s.identityKey = new(eddsa.PrivateKey)
		s.identityKey.FromBytes(s.cfg.Debug.IdentityKey.Bytes())
	} else {
		identityPrivateKeyFile := filepath.Join(s.cfg.Authority.DataDir, "identity.private.pem")
		identityPublicKeyFile := filepath.Join(s.cfg.Authority.DataDir, "identity.public.pem")
		if s.identityKey, err = eddsa.Load(identityPrivateKeyFile, identityPublicKeyFile, rand.Reader); err != nil {
			s.log.Errorf("Failed to initialize identity: %v", err)
			return nil, err
		}
	}
	s.linkKey = s.identityKey.ToECDH()
	s.log.Noticef("Authority identity public key is: %s", s.identityKey.PublicKey())

	if s.cfg.Debug.GenerateOnly {
		return nil, ErrGenerateOnly
	}

	// Ensure that there are enough mixes and providers whitelisted to form
	// a topology, assuming all of them post a descriptor.
	if len(cfg.Providers) < 1 {
		return nil, fmt.Errorf("server: No Providers specified in the config")
	}
	if len(cfg.Mixes) < cfg.Debug.Layers*cfg.Debug.MinNodesPerLayer {
		return nil, fmt.Errorf("server: Insufficient nodes whitelisted, got %v , need %v", len(cfg.Mixes), cfg.Debug.Layers*cfg.Debug.MinNodesPerLayer)
	}

	// Past this point, failures need to call s.Shutdown() to do cleanup.
	isOk := false
	defer func() {
		if !isOk {
			s.Shutdown()
		}
	}()

	// Start the fatal error watcher.
	go func() {
		err, ok := <-s.fatalErrCh
		if !ok {
			return
		}
		s.log.Warningf("Shutting down due to error: %v", err)
		s.Shutdown()
	}()

	// Start up the state worker.
	if s.state, err = newState(s); err != nil {
		return nil, err
	}

	// Start up the listeners.
	for _, v := range s.cfg.Authority.Addresses {
		l, err := net.Listen("tcp", v)
		if err != nil {
			s.log.Errorf("Failed to start listener '%v': %v", v, err)
			continue
		}
		s.listeners = append(s.listeners, l)
		s.Add(1)
		go s.listenWorker(l)
	}
	if len(s.listeners) == 0 {
		s.log.Errorf("Failed to start all listeners.")
		return nil, fmt.Errorf("authority: failed to start all listeners")
	}

	isOk = true
	return s, nil
}
