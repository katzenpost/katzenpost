// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	replicaCommon "github.com/katzenpost/katzenpost/replica/common"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/sign"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/utils"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/replica/config"
)

// PendingProxyRequest represents a proxy request waiting for a response
type PendingProxyRequest struct {
	ResponseCh chan *commands.ReplicaMessageReply
	Timeout    time.Time
}

// ProxyRequestManager manages pending proxy requests
type ProxyRequestManager struct {
	sync.RWMutex
	pendingRequests map[[32]byte]*PendingProxyRequest
	log             *logging.Logger
}

// NewProxyRequestManager creates a new proxy request manager
func NewProxyRequestManager(log *logging.Logger) *ProxyRequestManager {
	return &ProxyRequestManager{
		pendingRequests: make(map[[32]byte]*PendingProxyRequest),
		log:             log,
	}
}

// RegisterRequest registers a new proxy request and returns a response channel
func (p *ProxyRequestManager) RegisterRequest(envelopeHash [32]byte, timeout time.Duration) chan *commands.ReplicaMessageReply {
	p.Lock()
	defer p.Unlock()

	responseCh := make(chan *commands.ReplicaMessageReply, 1)
	p.pendingRequests[envelopeHash] = &PendingProxyRequest{
		ResponseCh: responseCh,
		Timeout:    time.Now().Add(timeout),
	}

	p.log.Debugf("Registered proxy request for envelope hash: %x", envelopeHash)
	return responseCh
}

// HandleReply processes an incoming reply and routes it to the waiting request
func (p *ProxyRequestManager) HandleReply(reply *commands.ReplicaMessageReply) bool {
	if reply.EnvelopeHash == nil {
		p.log.Warningf("Received reply with nil envelope hash")
		return false
	}

	p.Lock()
	defer p.Unlock()

	request, exists := p.pendingRequests[*reply.EnvelopeHash]
	if !exists {
		p.log.Debugf("No pending request found for envelope hash: %x", reply.EnvelopeHash)
		return false
	}

	// Send the reply to the waiting channel
	select {
	case request.ResponseCh <- reply:
		p.log.Debugf("PROXY REPLY ROUTED: Successfully routed reply to waiting proxy request for envelope hash: %x", reply.EnvelopeHash)
	default:
		p.log.Warningf("PROXY REPLY FAILED: Failed to send reply to channel for envelope hash: %x", reply.EnvelopeHash)
	}

	// Clean up the request
	delete(p.pendingRequests, *reply.EnvelopeHash)
	close(request.ResponseCh)
	return true
}

// CleanupExpiredRequests removes expired requests
func (p *ProxyRequestManager) CleanupExpiredRequests() {
	p.Lock()
	defer p.Unlock()

	now := time.Now()
	for hash, request := range p.pendingRequests {
		if now.After(request.Timeout) {
			p.log.Debugf("Cleaning up expired proxy request for envelope hash: %x", hash)
			close(request.ResponseCh)
			delete(p.pendingRequests, hash)
		}
	}
}

// ErrGenerateOnly is the error returned when the server initialization
// terminates due to the `GenerateOnly` debug config option.
var ErrGenerateOnly = errors.New("server: GenerateOnly set")

type GenericListener interface {
	Halt()
	CloseOldConns(interface{}) error
	GetConnIdentities() (map[[constants.RecipientIDLength]byte]interface{}, error)
}

type GenericConnector interface {
	Halt()
	Server() *Server
	OnClosedConn(conn *outgoingConn)
	CloseAllCh() chan interface{}
	ForceUpdate()
	DispatchCommand(cmd commands.Command, idHash *[32]byte)
	DispatchReplication(cmd *commands.ReplicaWrite)
}

type Server struct {
	sync.WaitGroup

	cfg *config.Config

	PKIWorker *PKIWorker
	listeners []GenericListener
	state     *state
	connector GenericConnector

	identityPrivateKey sign.PrivateKey
	identityPublicKey  sign.PublicKey
	linkKey            kem.PrivateKey

	envelopeKeys *EnvelopeKeys

	// Proxy request management for replica-to-replica communication
	proxyRequestManager *ProxyRequestManager

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
			return fmt.Errorf("replica: failed to stat() DataDir: %v", err)
		}
		if err = os.Mkdir(d, dirMode); err != nil {
			return fmt.Errorf("replica: failed to create DataDir: %v", err)
		}
	} else {
		if !fi.IsDir() {
			return fmt.Errorf("replica: DataDir '%v' is not a directory", d)
		}
		if fi.Mode() != dirMode {
			return fmt.Errorf("replica: DataDir '%v' has invalid permissions '%v'", d, fi.Mode())
		}
	}

	return nil
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
		s.log = s.logBackend.GetLogger("replica")
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

	// First halt all listeners to stop accepting new connections
	for _, listener := range s.listeners {
		listener.Halt()
	}

	// Then halt the connector to stop outgoing connections
	if s.connector != nil {
		s.connector.Halt()
	}

	// Now it's safe to close the database since no more requests are coming in
	if s.state != nil {
		s.state.Close()
	}

	// Finally halt other components
	if s.envelopeKeys != nil {
		s.envelopeKeys.Halt()
	}

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

// New returns a new Server instance parameterized with the specific
// configuration.
func New(cfg *config.Config) (*Server, error) {
	return NewWithPKI(cfg, nil)
}

// NewWithPKI returns a new Server instance with a custom PKI implementation.
// If pkiFactory is nil, the default PKI worker is used.
func NewWithPKI(cfg *config.Config, pkiClient pki.Client) (*Server, error) {
	return newServerWithPKI(cfg, pkiClient)
}

// newServerWithPKI is the internal implementation that supports both PKI factory and PKI client
func newServerWithPKI(cfg *config.Config, pkiClient pki.Client) (*Server, error) {
	s := new(Server)
	s.cfg = cfg

	// Do the early initialization and bring up logging.
	if err := s.initDataDir(); err != nil {
		return nil, err
	}
	if err := s.initLogging(); err != nil {
		return nil, err
	}

	s.state = newState(s)
	s.state.initDB()

	// Initialize proxy request manager
	s.proxyRequestManager = NewProxyRequestManager(s.log)

	// Start cleanup worker for expired proxy requests
	go s.proxyRequestCleanupWorker()

	s.fatalErrCh = make(chan error)
	s.haltedCh = make(chan interface{})

	s.log.Notice("Starting Katzenpost Pigeonhole Storage Replica")
	if s.cfg.Logging.Level == "DEBUG" {
		s.log.Warning("Debug logging is enabled.")
	}

	// Initialize cryptographic keys
	if err := s.initIdentityKeys(); err != nil {
		return nil, err
	}
	if err := s.initLinkKeys(); err != nil {
		return nil, err
	}
	if err := s.initEnvelopeKeys(); err != nil {
		return nil, err
	}

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

	if err := s.startServices(pkiClient); err != nil {
		return nil, err
	}

	isOk = true

	// Check if we have a PKI document before rebalancing
	if s.PKIWorker.HasCurrentPKIDocument() {
		s.log.Notice("performing rebalance after startup")
		err := s.state.Rebalance()
		if err != nil {
			s.log.Errorf("failed to rebalance shares after startup: %s", err)
		}
	} else {
		s.log.Notice("skipping initial rebalance - no PKI document available yet")
	}

	return s, nil
}

// initIdentityKeys initializes the server's identity keypair
func (s *Server) initIdentityKeys() error {
	s.log.Debug("ensuring identity keypair exists")
	identityPrivateKeyFile := filepath.Join(s.cfg.DataDir, "identity.private.pem")
	identityPublicKeyFile := filepath.Join(s.cfg.DataDir, "identity.public.pem")

	pkiSignatureScheme := signSchemes.ByName(s.cfg.PKISignatureScheme)
	if pkiSignatureScheme == nil {
		return errors.New("PKI Signature Scheme not found")
	}

	var err error
	s.identityPublicKey, s.identityPrivateKey, err = pkiSignatureScheme.GenerateKey()
	if err != nil {
		return err
	}

	if utils.BothExists(identityPrivateKeyFile, identityPublicKeyFile) {
		s.log.Noticef("Using Identity keypair which already exists: %s and %s", identityPrivateKeyFile, identityPublicKeyFile)
		s.identityPrivateKey, err = signpem.FromPrivatePEMFile(identityPrivateKeyFile, pkiSignatureScheme)
		if err != nil {
			return err
		}
		s.identityPublicKey, err = signpem.FromPublicPEMFile(identityPublicKeyFile, pkiSignatureScheme)
		if err != nil {
			return err
		}
	} else if utils.BothNotExists(identityPrivateKeyFile, identityPublicKeyFile) {
		s.log.Noticef("Identity keypair does not exist, creating new keypair: %s and %s", identityPrivateKeyFile, identityPublicKeyFile)
		err = signpem.PrivateKeyToFile(identityPrivateKeyFile, s.identityPrivateKey)
		if err != nil {
			return err
		}
		err = signpem.PublicKeyToFile(identityPublicKeyFile, s.identityPublicKey)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("%s and %s must either both exist or not exist", identityPrivateKeyFile, identityPublicKeyFile)
	}

	return nil
}

// initLinkKeys initializes the server's link keypair
func (s *Server) initLinkKeys() error {
	s.log.Debug("ensuring link keypair exists")
	scheme := kemSchemes.ByName(s.cfg.WireKEMScheme)
	if scheme == nil {
		return errors.New("KEM scheme not found in registry")
	}
	linkPrivateKeyFile := filepath.Join(s.cfg.DataDir, "link.private.pem")
	linkPublicKeyFile := filepath.Join(s.cfg.DataDir, "link.public.pem")

	linkPublicKey, linkPrivateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		return err
	}

	if utils.BothExists(linkPrivateKeyFile, linkPublicKeyFile) {
		s.log.Noticef("Using Link keypair which already exists: %s and %s", linkPrivateKeyFile, linkPublicKeyFile)
		linkPrivateKey, err = kempem.FromPrivatePEMFile(linkPrivateKeyFile, scheme)
		if err != nil {
			return err
		}
		_, err = kempem.FromPublicPEMFile(linkPublicKeyFile, scheme)
		if err != nil {
			return err
		}
	} else if utils.BothNotExists(linkPrivateKeyFile, linkPublicKeyFile) {
		s.log.Noticef("Link keypair does not exist, creating new keypair: %s and %s", linkPrivateKeyFile, linkPublicKeyFile)
		err = kempem.PrivateKeyToFile(linkPrivateKeyFile, linkPrivateKey)
		if err != nil {
			return err
		}
		err = kempem.PublicKeyToFile(linkPublicKeyFile, linkPublicKey)
		if err != nil {
			return err
		}
	} else {
		panic("Improbable: Only found one link PEM file.")
	}

	s.linkKey = linkPrivateKey
	return nil
}

// initEnvelopeKeys initializes the server's envelope keys
func (s *Server) initEnvelopeKeys() error {
	s.log.Debug("ensuring replica NIKE keypair exists")
	nikeScheme := nikeSchemes.ByName(s.cfg.ReplicaNIKEScheme)
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	var err error
	s.envelopeKeys, err = NewEnvelopeKeys(nikeScheme, s.logBackend.GetLogger("replica envelopeKeys"), s.cfg.DataDir, replicaEpoch)
	s.log.Debug("AFTER ensuring replica NIKE keypair exists")
	if err != nil {
		panic(err)
	}
	return nil
}

// startServices starts all the server services (PKI worker, listeners, connector)
func (s *Server) startServices(pkiClient pki.Client) error {
	// Start the fatal error watcher.
	go func() {
		err, ok := <-s.fatalErrCh
		if !ok {
			return
		}
		s.log.Warningf("Shutting down due to error: %v", err)
		s.Shutdown()
	}()

	var addresses []string
	if len(s.cfg.BindAddresses) > 0 {
		s.log.Debugf("BindAddresses found")
		addresses = s.cfg.BindAddresses
	} else {
		addresses = s.cfg.Addresses
	}

	// Start the PKI worker.
	s.log.Notice("start PKI worker")
	var pkiWorker *PKIWorker
	var err error
	if pkiClient != nil {
		// Use the provided PKI client for testing
		pkiWorker, err = newPKIWorkerWithClient(s, pkiClient, s.logBackend.GetLogger("replica pkiWorker"))
	} else {
		// Use the default PKI worker
		pkiWorker, err = newPKIWorker(s, s.logBackend.GetLogger("replica pkiWorker"))
	}
	if err != nil {
		panic(err)
	}
	s.PKIWorker = pkiWorker

	// Bring the listener(s) online.
	s.log.Notice("start listener workers")
	s.listeners = make([]GenericListener, 0, len(addresses))
	for i, addr := range addresses {
		l, err := newListener(s, i, addr)
		if err != nil {
			s.log.Errorf("Failed to spawn listener on address: %v (%v).", addr, err)
			return err
		}
		s.listeners = append(s.listeners, l)
	}

	// Start the outgoing connection worker
	s.log.Notice("start connector worker")
	s.connector = newConnector(s)

	return nil
}

// proxyRequestCleanupWorker periodically cleans up expired proxy requests
func (s *Server) proxyRequestCleanupWorker() {
	ticker := time.NewTicker(30 * time.Second) // Clean up every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-s.haltedCh:
			s.log.Debug("Proxy request cleanup worker terminating")
			return
		case <-ticker.C:
			s.proxyRequestManager.CleanupExpiredRequests()
		}
	}
}
