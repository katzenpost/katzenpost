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

	DispatchMessage(dest uint8, message *commands.ReplicaMessage)
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

	err := utils.MkDataDir(s.cfg.DataDir)
	if err != nil {
		return nil, err
	}
	err = s.initLogging()
	if err != nil {
		return nil, err
	}

	// Create PKI worker with injected client or default client
	if pkiClient != nil {
		s.PKI, err = newPKIWorker(s, pkiClient, s.logBackend.GetLogger("courier-pkiworker"))
	} else {
		s.PKI, err = newPKIWorkerWithDefaultClient(s, s.logBackend.GetLogger("courier-pkiworker"))
	}
	if err != nil {
		return nil, err
	}

	// Initialize identity keys
	identityPrivateKeyFile := filepath.Join(s.cfg.DataDir, "identity.private.pem")
	identityPublicKeyFile := filepath.Join(s.cfg.DataDir, "identity.public.pem")

	pkiSignatureScheme := signSchemes.ByName(cfg.PKIScheme)
	if pkiSignatureScheme == nil {
		panic("PKI signature scheme not found")
	}

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
		panic("Improbable: Only found one identity PEM file.")
	}

	// read our service node's link keys
	linkPrivateKeyFile := filepath.Join(s.cfg.DataDir, "link.private.pem")
	linkPublicKeyFile := filepath.Join(s.cfg.DataDir, "link.public.pem")

	scheme := schemes.ByName(cfg.WireKEMScheme)
	if scheme == nil {
		panic("KEM scheme not found")
	}

	var linkPublicKey kem.PublicKey
	var linkPrivateKey kem.PrivateKey

	if utils.BothExists(linkPrivateKeyFile, linkPublicKeyFile) {
		linkPrivateKey, err = pemkem.FromPrivatePEMFile(linkPrivateKeyFile, scheme)
		if err != nil {
			return nil, err
		}
		linkPublicKey, err = pemkem.FromPublicPEMFile(linkPublicKeyFile, scheme)
		if err != nil {
			return nil, err
		}
	} else if utils.BothNotExists(linkPrivateKeyFile, linkPublicKeyFile) {
		panic("No link keys found.")
	} else {
		panic("Improbable: Only found one link PEM file.")
	}
	s.linkPrivKey = linkPrivateKey
	s.linkPubKey = linkPublicKey

	s.connector = newConnector(s)

	// Initialize the Courier plugin for testing
	nikeScheme := nikeSchemes.ByName(cfg.EnvelopeScheme)
	cmds := commands.NewStorageReplicaCommands(cfg.SphinxGeometry, nikeScheme)
	s.Courier = NewCourier(s, cmds, nikeScheme)

	return s, nil
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

func (s *Server) SendMessage(dest uint8, mesg *commands.ReplicaMessage) {
	s.connector.DispatchMessage(dest, mesg)
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
