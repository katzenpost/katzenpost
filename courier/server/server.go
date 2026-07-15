// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"path/filepath"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/kem"
	pemkem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"

	kpcommon "github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/utils"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/courier/server/config"
	"github.com/katzenpost/katzenpost/courier/server/instrument"
)

type GenericConnector interface {
	Halt()
	Server() *Server
	OnClosedConn(conn *outgoingConn)
	CloseAllCh() chan interface{}
	ForceUpdate()

	DispatchMessage(dest uint8, message *commands.ReplicaMessage) error
}

type Server struct {
	cfg *config.Config

	Courier *Courier

	logBackend *log.Backend
	log        *logging.Logger

	linkPrivKey kem.PrivateKey
	linkPubKey  kem.PublicKey

	PKI       *PKIWorker
	connector GenericConnector
}

// NewWithDefaultPKI creates a new Server with the default voting PKI client
func NewWithDefaultPKI(cfg *config.Config) (*Server, error) {
	return New(cfg, nil)
}

// NewWithPKI creates a new Server with a custom PKI client for testing
func NewWithPKI(cfg *config.Config, pkiClient pki.Fetcher) (*Server, error) {
	return New(cfg, pkiClient)
}

func New(cfg *config.Config, pkiClient pki.Fetcher) (*Server, error) {
	s := &Server{
		cfg: cfg,
	}

	if err := s.initializeBasics(); err != nil {
		return nil, err
	}

	if err := s.initializePKI(pkiClient); err != nil {
		return nil, err
	}

	if err := s.initializeLinkKeys(); err != nil {
		return nil, err
	}

	s.initializeServices()

	if cfg.MetricsAddress != "" {
		s.log.Noticef("Starting prometheus metrics listener on %s", cfg.MetricsAddress)
	} else {
		s.log.Notice("Prometheus metrics listener disabled (MetricsAddress not set)")
	}
	instrument.StartPrometheusListener(cfg.MetricsAddress)

	return s, nil
}

// initializeBasics sets up data directory and logging
func (s *Server) initializeBasics() error {
	if err := utils.MkDataDir(s.cfg.DataDir); err != nil {
		return err
	}
	return s.initLogging()
}

// initializePKI sets up the PKI worker
func (s *Server) initializePKI(pkiClient pki.Fetcher) error {
	var err error
	if pkiClient != nil {
		s.PKI, err = newPKIWorker(s, pkiClient, s.logBackend.GetLogger("courier-pkiworker"))
	} else {
		s.PKI, err = newPKIWorkerWithDefaultClient(s, s.logBackend.GetLogger("courier-pkiworker"))
	}
	return err
}

// initializeLinkKeys sets up link keys for the server
func (s *Server) initializeLinkKeys() error {
	linkPrivateKeyFile := filepath.Join(s.cfg.DataDir, "link.private.pem")
	linkPublicKeyFile := filepath.Join(s.cfg.DataDir, "link.public.pem")

	scheme := schemes.ByName(s.cfg.WireKEMScheme)
	if scheme == nil {
		panic("KEM scheme not found")
	}

	var linkPublicKey kem.PublicKey
	var linkPrivateKey kem.PrivateKey
	var err error

	if utils.BothExists(linkPrivateKeyFile, linkPublicKeyFile) {
		linkPrivateKey, err = pemkem.FromPrivatePEMFile(linkPrivateKeyFile, scheme)
		if err != nil {
			return err
		}
		linkPublicKey, err = pemkem.FromPublicPEMFile(linkPublicKeyFile, scheme)
		if err != nil {
			return err
		}
	} else if utils.BothNotExists(linkPrivateKeyFile, linkPublicKeyFile) {
		panic("No link keys found.")
	} else {
		panic("Improbable: Only found one link PEM file.")
	}
	s.linkPrivKey = linkPrivateKey
	s.linkPubKey = linkPublicKey
	return nil
}

// initializeServices sets up connector and courier services
func (s *Server) initializeServices() {
	// Initialize the Courier plugin first (before connector)
	nikeScheme := nikeSchemes.ByName(s.cfg.EnvelopeScheme)
	cmds := commands.NewStorageReplicaCommands(s.cfg.SphinxGeometry, nikeScheme)
	s.Courier = NewCourier(s, cmds, nikeScheme)

	// Initialize connector after courier is ready
	s.connector = newConnector(s)
}

func (s *Server) LogBackend() *log.Backend {
	return s.logBackend
}

func (s *Server) initLogging() error {
	p := s.cfg.Logging.File
	if p == "" {
		p = filepath.Join(s.cfg.DataDir, "courier.log")
	} else if !filepath.IsAbs(p) {
		p = filepath.Join(s.cfg.DataDir, p)
	}

	var err error
	s.logBackend, err = log.New(p, s.cfg.Logging.Level, s.cfg.Logging.Disable)
	if err == nil {
		s.log = s.logBackend.GetLogger("courier server")
		s.log.Noticef("Katzenpost courier version: %s", kpcommon.Version())
		s.log.Notice("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")
	}
	return err
}

func (s *Server) SendMessage(dest uint8, mesg *commands.ReplicaMessage) error {
	return s.connector.DispatchMessage(dest, mesg)
}

func (s *Server) ForceConnectorUpdate() {
	s.connector.ForceUpdate()
}

// LinkPublicKey returns the server's link public key
func (s *Server) LinkPublicKey() kem.PublicKey {
	return s.linkPubKey
}
