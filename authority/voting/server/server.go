// server.go - Katzenpost voting authority server.
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

// Package server implements the Katzenpost voting authority server.
package server

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"github.com/quic-go/quic-go"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/sign"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/utils"
	"github.com/katzenpost/katzenpost/http/common"
)

// ErrGenerateOnly is the error returned when the server initialization
// terminates due to the `GenerateOnly` debug config option.
var ErrGenerateOnly = errors.New("server: GenerateOnly set")

// Server is a voting authority server instance.
type Server struct {
	sync.WaitGroup

	cfg *config.Config
	geo *geo.Geometry

	identityPrivateKey sign.PrivateKey
	identityPublicKey  sign.PublicKey
	linkKey            kem.PrivateKey

	logBackend *log.Backend
	log        *logging.Logger

	state     *state
	listeners []net.Listener

	fatalErrCh chan error
	haltedCh   chan interface{}
	haltOnce   sync.Once
}

func computeLambdaG(cfg *config.Config) float64 {
	n := float64(len(cfg.Topology.Layers[0].Nodes))
	if n == 1 {
		return cfg.Parameters.LambdaP + cfg.Parameters.LambdaL + cfg.Parameters.LambdaD
	}
	return n * math.Log(n)
}

func (s *Server) initDataDir() error {
	const dirMode = os.ModeDir | 0700
	d := s.cfg.Server.DataDir

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
			return fmt.Errorf("authority: DataDir '%v' has invalid permissions '%v'", d, fi.Mode())
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
		s.log = s.logBackend.GetLogger("authority")
	}
	return err
}

// IdentityKey returns the running Server's identity public key.
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

	close(s.fatalErrCh)

	s.log.Notice("Shutdown complete.")
	close(s.haltedCh)
}

// New returns a new Server instance parameterized with the specific
// configuration.
func New(cfg *config.Config) (*Server, error) {
	s := new(Server)
	s.cfg = cfg
	s.geo = cfg.SphinxGeometry

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

	pkiSignatureScheme := signSchemes.ByName(cfg.Server.PKISignatureScheme)

	// Initialize the authority identity key.
	identityPrivateKeyFile := filepath.Join(s.cfg.Server.DataDir, "identity.private.pem")
	identityPublicKeyFile := filepath.Join(s.cfg.Server.DataDir, "identity.public.pem")

	var err error

	if utils.BothExists(identityPrivateKeyFile, identityPublicKeyFile) {
		s.identityPrivateKey, err = signpem.FromPrivatePEMFile(identityPrivateKeyFile, pkiSignatureScheme)
		if err != nil {
			return nil, err
		}
		s.identityPublicKey, err = signpem.FromPublicPEMFile(identityPublicKeyFile, pkiSignatureScheme)
		if err != nil {
			return nil, err
		}
	} else if utils.BothNotExists(identityPrivateKeyFile, identityPublicKeyFile) {
		s.identityPublicKey, s.identityPrivateKey, err = pkiSignatureScheme.GenerateKey()
		if err != nil {
			return nil, err
		}
		err = signpem.PrivateKeyToFile(identityPrivateKeyFile, s.identityPrivateKey)
		if err != nil {
			return nil, err
		}
		err = signpem.PublicKeyToFile(identityPublicKeyFile, s.identityPublicKey)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("%s and %s must either both exist or not exist", identityPrivateKeyFile, identityPublicKeyFile)
	}

	scheme := schemes.ByName(cfg.Server.WireKEMScheme)
	if scheme == nil {
		return nil, errors.New("KEM scheme not found in registry")
	}
	linkPrivateKeyFile := filepath.Join(s.cfg.Server.DataDir, "link.private.pem")
	linkPublicKeyFile := filepath.Join(s.cfg.Server.DataDir, "link.public.pem")

	var linkPrivateKey kem.PrivateKey

	if utils.BothExists(linkPrivateKeyFile, linkPublicKeyFile) {
		linkPrivateKey, err = kempem.FromPrivatePEMFile(linkPrivateKeyFile, scheme)
		if err != nil {
			return nil, err
		}
		_, err = kempem.FromPublicPEMFile(linkPublicKeyFile, scheme)
		if err != nil {
			return nil, err
		}

		/* NOTE(david): enable this check after we get things working again?
		linkpubkey, err := kempem.FromPublicPEMFile(linkPublicKeyFile, scheme)
		if err != nil {
			return nil, err
		}
		s.log.Warning("attempting to call validate our config's peers against our own link public key")
		err = cfg.ValidateAuthorities(linkpubkey)
		if err != nil {
			s.log.Error("config's peers validation failure. must be your own peer!")
			return nil, err
		}
		*/
	} else if utils.BothNotExists(linkPrivateKeyFile, linkPublicKeyFile) {
		linkPublicKey, linkPrivateKey, err := scheme.GenerateKeyPair()
		if err != nil {
			return nil, err
		}

		err = kempem.PrivateKeyToFile(linkPrivateKeyFile, linkPrivateKey)
		if err != nil {
			return nil, err
		}
		err = kempem.PublicKeyToFile(linkPublicKeyFile, linkPublicKey)
		if err != nil {
			return nil, err
		}
	} else {
		panic("Improbable: Only found one link PEM file.")
	}

	s.linkKey = linkPrivateKey

	s.log.Noticef("Authority identity public key hash is: %x", hash.Sum256From(s.identityPublicKey))
	linkBlob, err := s.linkKey.Public().MarshalBinary()
	if err != nil {
		return nil, err
	}
	s.log.Noticef("Authority link public key hash is: %x", sha256.Sum256(linkBlob))

	if s.cfg.Debug.GenerateOnly {
		return nil, ErrGenerateOnly
	}

	// Ensure that there are enough mixes and providers whitelisted to form
	// a topology, assuming all of them post a descriptor.
	if len(cfg.GatewayNodes) < 1 {
		return nil, fmt.Errorf("server: No GatewayNodes specified in the config")
	}
	if len(cfg.ServiceNodes) < 1 {
		return nil, fmt.Errorf("server: No ServiceNodes specified in the config")
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
	s.state.Go(s.state.worker)

	// Start up the listeners.
	for _, v := range s.cfg.Server.Addresses {
		// parse the Address line as a URL
		u, err := url.Parse(v)
		if err == nil {
			switch u.Scheme {
			case "tcp":
				l, err := net.Listen("tcp", u.Host)
				if err != nil {
					s.log.Errorf("Failed to start listener '%v': %v", v, err)
					continue
				}
				s.listeners = append(s.listeners, l)
				s.Add(1)
				s.state.Go(func() {
					s.listenWorker(l)
				})
			case "quic":
				l, err := quic.ListenAddr(u.Host, common.GenerateTLSConfig(), nil)
				if err != nil {
					s.log.Errorf("Failed to start listener '%v': %v", v, err)
					continue
				}
				// Wrap quic.Listener with common.QuicListener
				// so it implements like net.Listener for a
				// single QUIC Stream
				ql := common.QuicListener{Listener: l}
				s.listeners = append(s.listeners, &ql)
				s.Add(1)
				s.state.Go(func() {
					s.listenWorker(&ql)
				})
			default:
				s.log.Errorf("Unsupported listener scheme '%v': %v", v, err)
				continue
			}
		}
	}
	if len(s.listeners) == 0 {
		s.log.Errorf("Failed to start all listeners.")
		return nil, fmt.Errorf("authority: failed to start all listeners")
	}

	isOk = true
	return s, nil
}
