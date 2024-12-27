// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"path/filepath"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/kem"
	pemkem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/utils"
	"github.com/katzenpost/katzenpost/core/wire"
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

type PKI interface {
	AuthenticateReplicaConnection(c *wire.PeerCredentials) (*pki.ReplicaDescriptor, bool)
	PKIDocument() *pki.Document
	ReplicasCopy() map[[32]byte]*pki.ReplicaDescriptor
}

type Server struct {
	cfg *config.Config

	logBackend *log.Backend
	log        *logging.Logger

	linkPrivKey kem.PrivateKey
	linkPubKey  kem.PublicKey

	pki       PKI
	connector GenericConnector
}

func defaultPKIFactory(s *Server) {
	var err error
	s.pki, err = newPKIWorker(s, s.logBackend.GetLogger("pkiclient"))
	if err != nil {
		panic(err)
	}
}

func New(cfg *config.Config, pkiFactory func(*Server)) (*Server, error) {
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

	// read our service node's link keys
	linkPrivateKeyFile := filepath.Join(s.cfg.ServiceNodeDataDir, "link.private.pem")
	linkPublicKeyFile := filepath.Join(s.cfg.ServiceNodeDataDir, "link.public.pem")

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

	if pkiFactory == nil {
		defaultPKIFactory(s)
	} else {
		pkiFactory(s)
	}

	s.connector = newConnector(s)

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
		s.log = s.logBackend.GetLogger("server")
	}
	return err
}

func (s *Server) SendMessage(dest uint8, mesg *commands.ReplicaMessage) {
	s.connector.DispatchMessage(dest, mesg)
}
