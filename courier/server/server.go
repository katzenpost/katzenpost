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
	"github.com/katzenpost/hpqc/sign"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/utils"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/courier/server/config"
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

	identityPrivateKey sign.PrivateKey
	identityPublicKey  sign.PublicKey

	PKI       *PKIWorker
	connector GenericConnector
}

// NewWithDefaultPKI creates a new Server with the default voting PKI client
func NewWithDefaultPKI(cfg *config.Config) (*Server, error) {
	return New(cfg, nil)
}

// NewWithPKI creates a new Server with a custom PKI client for testing
func NewWithPKI(cfg *config.Config, pkiClient pki.Client) (*Server, error) {
	return New(cfg, pkiClient)
}

func New(cfg *config.Config, pkiClient pki.Client) (*Server, error) {
	s := &Server{
		cfg: cfg,
	}

	if err := s.initializeBasics(); err != nil {
		return nil, err
	}

	if err := s.initializePKI(pkiClient); err != nil {
		return nil, err
	}

	if err := s.initializeIdentityKeys(); err != nil {
		return nil, err
	}

	if err := s.initializeLinkKeys(); err != nil {
		return nil, err
	}

	s.initializeServices()

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
func (s *Server) initializePKI(pkiClient pki.Client) error {
	var err error
	if pkiClient != nil {
		s.PKI, err = newPKIWorker(s, pkiClient, s.logBackend.GetLogger("courier-pkiworker"))
	} else {
		s.PKI, err = newPKIWorkerWithDefaultClient(s, s.logBackend.GetLogger("courier-pkiworker"))
	}
	return err
}

// initializeIdentityKeys sets up identity keys for the server
func (s *Server) initializeIdentityKeys() error {
	identityPrivateKeyFile := filepath.Join(s.cfg.DataDir, "identity.private.pem")
	identityPublicKeyFile := filepath.Join(s.cfg.DataDir, "identity.public.pem")

	pkiSignatureScheme := signSchemes.ByName(s.cfg.PKIScheme)
	if pkiSignatureScheme == nil {
		panic("PKI signature scheme not found")
	}

	if utils.BothExists(identityPrivateKeyFile, identityPublicKeyFile) {
		return s.loadExistingIdentityKeys(identityPrivateKeyFile, identityPublicKeyFile, pkiSignatureScheme)
	} else if utils.BothNotExists(identityPrivateKeyFile, identityPublicKeyFile) {
		return s.generateNewIdentityKeys(identityPrivateKeyFile, identityPublicKeyFile, pkiSignatureScheme)
	} else {
		panic("Improbable: Only found one identity PEM file.")
	}
}

// loadExistingIdentityKeys loads identity keys from existing files
func (s *Server) loadExistingIdentityKeys(privateFile, publicFile string, scheme sign.Scheme) error {
	var err error
	s.identityPrivateKey, err = signpem.FromPrivatePEMFile(privateFile, scheme)
	if err != nil {
		return err
	}
	s.identityPublicKey, err = signpem.FromPublicPEMFile(publicFile, scheme)
	return err
}

// generateNewIdentityKeys generates and saves new identity keys
func (s *Server) generateNewIdentityKeys(privateFile, publicFile string, scheme sign.Scheme) error {
	var err error
	s.identityPublicKey, s.identityPrivateKey, err = scheme.GenerateKey()
	if err != nil {
		return err
	}
	if err = signpem.PrivateKeyToFile(privateFile, s.identityPrivateKey); err != nil {
		return err
	}
	return signpem.PublicKeyToFile(publicFile, s.identityPublicKey)
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
	if !s.cfg.Logging.Disable && s.cfg.Logging.File != "" {
		if !filepath.IsAbs(p) {
			p = filepath.Join(s.cfg.DataDir, p)
		}
	}

	var err error
	s.logBackend, err = log.New(p, s.cfg.Logging.Level, s.cfg.Logging.Disable)
	if err == nil {
		s.log = s.logBackend.GetLogger("courier server")
	}
	return err
}

func (s *Server) SendMessage(dest uint8, mesg *commands.ReplicaMessage) error {
	return s.connector.DispatchMessage(dest, mesg)
}

func (s *Server) ForceConnectorUpdate() {
	s.connector.ForceUpdate()
}

// IdentityPublicKey returns the server's identity public key
func (s *Server) IdentityPublicKey() sign.PublicKey {
	return s.identityPublicKey
}

// LinkPublicKey returns the server's link public key
func (s *Server) LinkPublicKey() kem.PublicKey {
	return s.linkPubKey
}
