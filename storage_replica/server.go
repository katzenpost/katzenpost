// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"github.com/quic-go/quic-go"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikepem "github.com/katzenpost/hpqc/nike/pem"
	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/utils"
	"github.com/katzenpost/katzenpost/http/common"
	"github.com/katzenpost/katzenpost/storage_replica/config"
)

// ErrGenerateOnly is the error returned when the server initialization
// terminates due to the `GenerateOnly` debug config option.
var ErrGenerateOnly = errors.New("server: GenerateOnly set")

type Server struct {
	sync.WaitGroup

	cfg *config.Config

	replicaPrivateKey nike.PrivateKey
	replicaPublicKey  nike.PublicKey

	state     *state
	linkKey   kem.PrivateKey
	listeners []net.Listener

	logBackend *log.Backend
	log        *logging.Logger

	fatalErrCh chan error
	haltedCh   chan interface{}
	haltOnce   sync.Once
}

func (s *Server) initDataDir() error {
	const dirMode = os.ModeDir | 0700
	d := s.cfg.DataDir

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
			p = filepath.Join(s.cfg.DataDir, p)
		}
	}

	var err error
	s.logBackend, err = log.New(p, s.cfg.Logging.Level, s.cfg.Logging.Disable)
	if err == nil {
		s.log = s.logBackend.GetLogger("authority")
	}
	return err
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
	s.log.Noticef("Starting graceful shutdown.")
	close(s.fatalErrCh)
	s.log.Noticef("Shutdown complete.")
	close(s.haltedCh)
}

// RotateLog rotates the log file
// if logging to a file is enabled.
func (s *Server) RotateLog() {
	err := s.logBackend.Rotate()
	if err != nil {
		s.fatalErrCh <- fmt.Errorf("failed to rotate log file, shutting down server")
	}
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

	s.log.Notice("Katzenpost Pigeonhole Storage Replica")
	if s.cfg.Logging.Level == "DEBUG" {
		s.log.Warning("Debug logging is enabled.")
	}

	replicaNikeScheme := nikeSchemes.ByName(cfg.ReplicaNIKEScheme)

	// Initialize the authority replica key.
	replicaPrivateKeyFile := filepath.Join(s.cfg.DataDir, "replica.private.pem")
	replicaPublicKeyFile := filepath.Join(s.cfg.DataDir, "replica.public.pem")

	var err error

	if utils.BothExists(replicaPrivateKeyFile, replicaPublicKeyFile) {
		s.replicaPrivateKey, err = nikepem.FromPrivatePEMFile(replicaPrivateKeyFile, replicaNikeScheme)
		if err != nil {
			return nil, err
		}
		s.replicaPublicKey, err = nikepem.FromPublicPEMFile(replicaPublicKeyFile, replicaNikeScheme)
		if err != nil {
			return nil, err
		}
	} else if utils.BothNotExists(replicaPrivateKeyFile, replicaPublicKeyFile) {
		s.replicaPublicKey, s.replicaPrivateKey, err = replicaNikeScheme.GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		err = nikepem.PrivateKeyToFile(replicaPrivateKeyFile, s.replicaPrivateKey, replicaNikeScheme)
		if err != nil {
			return nil, err
		}
		err = nikepem.PublicKeyToFile(replicaPublicKeyFile, s.replicaPublicKey, replicaNikeScheme)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("%s and %s must either both exist or not exist", replicaPrivateKeyFile, replicaPublicKeyFile)
	}

	scheme := schemes.ByName(cfg.WireKEMScheme)
	if scheme == nil {
		return nil, errors.New("KEM scheme not found in registry")
	}
	linkPrivateKeyFile := filepath.Join(s.cfg.DataDir, "link.private.pem")
	linkPublicKeyFile := filepath.Join(s.cfg.DataDir, "link.public.pem")

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

	if s.cfg.GenerateOnly {
		return nil, ErrGenerateOnly
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

	// Start up the listeners.
	for _, v := range s.cfg.Addresses {
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
				// XXX: is there any HTTP3 specific stuff that we want to do?
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
