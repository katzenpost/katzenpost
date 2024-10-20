// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/blake2b"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikepem "github.com/katzenpost/hpqc/nike/pem"
	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/sign"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/utils"
	"github.com/katzenpost/katzenpost/replica/common"
	"github.com/katzenpost/katzenpost/replica/config"
)

// ErrGenerateOnly is the error returned when the server initialization
// terminates due to the `GenerateOnly` debug config option.
var ErrGenerateOnly = errors.New("server: GenerateOnly set")

type GenericListener interface {
	Halt()
	CloseOldConns(interface{}) error
	GetConnIdentities() (map[[constants.RecipientIDLength]byte]interface{}, error)
}

type Server struct {
	sync.WaitGroup

	cfg *config.Config

	thinClient *thin.ThinClient
	pkiWorker  *PKIWorker
	listeners  []GenericListener
	state      *state

	replicaPrivateKey  nike.PrivateKey
	replicaPublicKey   nike.PublicKey
	identityPrivateKey sign.PrivateKey
	identityPublicKey  sign.PublicKey
	linkKey            kem.PrivateKey

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
	s.state.Close()
	for _, listener := range s.listeners {
		listener.Halt()
	}
}

// RotateLog rotates the log file
// if logging to a file is enabled.
func (s *Server) RotateLog() {
	err := s.logBackend.Rotate()
	if err != nil {
		s.fatalErrCh <- fmt.Errorf("failed to rotate log file, shutting down server")
	}
}

func (s *Server) HasLocalReplica(shards []*pki.ReplicaDescriptor) (bool, error) {
	for _, idKey := range shards {
		if s.identityPublicKey.Equal(idKey) {
			return true, nil
		}
	}
	return false, nil
}

func (s *Server) GetRemoteShards(id *[32]byte) ([]*pki.ReplicaDescriptor, error) {
	doc := s.thinClient.PKIDocument()
	replicaKeys, err := common.GetReplicaKeys(doc)
	if err != nil {
		return nil, err
	}
	orderedKeys := common.Shard(id, replicaKeys)
	shards := make([]*pki.ReplicaDescriptor, common.K)
	idKey, err := s.identityPublicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	for i, key := range orderedKeys {
		if hmac.Equal(key, idKey) {
			continue
		}
		hash := blake2b.Sum256(key)
		desc, err := doc.GetReplicaNodeByKeyHash(&hash)
		if err != nil {
			return nil, err
		}
		shards[i] = desc
		if i == common.K-1 {
			break
		}
	}
	return shards, nil
}

// New returns a new Server instance parameterized with the specific
// configuration.
func New(cfg *config.Config) (*Server, error) {
	s := new(Server)
	s.cfg = cfg
	s.state = newState(s)
	s.state.initDB()

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

	// Initialize the server identity and link keys.
	identityPrivateKeyFile := filepath.Join(s.cfg.DataDir, "identity.private.pem")
	identityPublicKeyFile := filepath.Join(s.cfg.DataDir, "identity.public.pem")

	var err error
	pkiSignatureScheme := signSchemes.ByName(s.cfg.PKISignatureScheme)
	if s == nil {
		return nil, errors.New("PKI Signature Scheme not found")
	}
	s.identityPublicKey, s.identityPrivateKey, err = pkiSignatureScheme.GenerateKey()

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

	replicaNikeScheme := nikeSchemes.ByName(cfg.ReplicaNIKEScheme)

	// Initialize the authority replica key.
	replicaPrivateKeyFile := filepath.Join(s.cfg.DataDir, "replica.private.pem")
	replicaPublicKeyFile := filepath.Join(s.cfg.DataDir, "replica.public.pem")

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

	linkPublicKey, linkPrivateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

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

	var addresses []string
	if len(s.cfg.BindAddresses) > 0 {
		s.log.Debugf("BindAddresses found")
		addresses = s.cfg.BindAddresses
	} else {
		addresses = s.cfg.Addresses
	}

	// Use thin client to connect o client2 daemon and gather a PKI document
	// which we will use for both wire authentication and for getting other replica keys
	// for use in our replica storage protocol.
	s.thinClient = thin.NewThinClient(s.cfg.ThinConfig)
	err = s.thinClient.Dial()
	if err != nil {
		s.log.Errorf("thinClient.Dial failure: %v", err)
		isOk = false
		return nil, err
	}

	// Start the PKI worker.
	s.pkiWorker = newPKIWorker(s, s.logBackend.GetLogger("pkiWorker"))

	// Bring the listener(s) online.
	s.listeners = make([]GenericListener, 0, len(addresses))
	for i, addr := range addresses {
		l, err := newListener(s, i, addr)
		if err != nil {
			s.log.Errorf("Failed to spawn listener on address: %v (%v).", addr, err)
			return nil, err
		}
		s.listeners = append(s.listeners, l)
	}

	isOk = true
	return s, nil
}
