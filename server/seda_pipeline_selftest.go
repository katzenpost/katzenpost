package server

import (
	"fmt"
	"net"
	"path/filepath"

	"gitlab.com/yawning/aez.git"
	"gopkg.in/eapache/channels.v1"

	nyquistkem "github.com/katzenpost/nyquist/kem"
	"github.com/katzenpost/nyquist/seec"

	"github.com/katzenpost/hpqc/hash"
	pemkem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
	signpem "github.com/katzenpost/hpqc/sign/pem"

	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/utils"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/cryptoworker"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/incoming"
	"github.com/katzenpost/katzenpost/server/internal/outgoing"
	"github.com/katzenpost/katzenpost/server/internal/provider"
	"github.com/katzenpost/katzenpost/server/internal/scheduler"
)

func NewSedaPipelineSelfTest(cfg *config.Config) (*Server, error) {
	s := &Server{
		cfg:        cfg,
		fatalErrCh: make(chan error),
		haltedCh:   make(chan interface{}),
	}
	goo := &serverGlue{s}

	// Do the early initialization and bring up logging.
	if err := utils.MkDataDir(s.cfg.Server.DataDir); err != nil {
		return nil, err
	}
	if err := s.initLogging(); err != nil {
		return nil, err
	}

	s.log.Notice("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")
	if s.cfg.Logging.Level == "DEBUG" {
		s.log.Warning("Unsafe Debug logging is enabled.")
	}
	if aez.IsHardwareAccelerated() {
		s.log.Noticef("AEZv5 implementation is hardware accelerated.")
	} else {
		s.log.Warningf("AEZv5 implementation IS NOT hardware accelerated.")
	}
	s.log.Noticef("Server identifier is: '%v'", s.cfg.Server.Identifier)
	s.log.Noticef("Sphinx Geometry: %s", cfg.SphinxGeometry.Display())

	// Initialize the server identity and link keys.
	identityPrivateKeyFile := filepath.Join(s.cfg.Server.DataDir, "identity.private.pem")
	identityPublicKeyFile := filepath.Join(s.cfg.Server.DataDir, "identity.public.pem")

	var err error
	s.identityPublicKey, s.identityPrivateKey, err = cert.Scheme.GenerateKey()

	if utils.BothExists(identityPrivateKeyFile, identityPublicKeyFile) {
		s.identityPrivateKey, err = signpem.FromPrivatePEMFile(identityPrivateKeyFile, cert.Scheme)
		if err != nil {
			return nil, err
		}
		s.identityPublicKey, err = signpem.FromPublicPEMFile(identityPublicKeyFile, cert.Scheme)
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

	idPubKeyHash := hash.Sum256From(s.identityPublicKey)
	s.log.Noticef("Server identity public key hash is: %x", idPubKeyHash[:])
	linkPrivateKeyFile := filepath.Join(s.cfg.Server.DataDir, "link.private.pem")
	linkPublicKeyFile := filepath.Join(s.cfg.Server.DataDir, "link.public.pem")
	scheme := schemes.ByName(cfg.Server.WireKEM)
	if scheme == nil {
		panic("KEM scheme not found")
	}

	//GenerateKeypair
	linkPublicKey, linkPrivateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
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
		rng, err := seec.GenKeyPassthrough(rand.Reader, 0)
		if err != nil {
			panic(err)
		}
		linkPublicKey, linkPrivateKey := nyquistkem.GenerateKeypair(scheme, rng)
		err = pemkem.PrivateKeyToFile(linkPrivateKeyFile, linkPrivateKey)
		if err != nil {
			return nil, err
		}
		err = pemkem.PublicKeyToFile(linkPublicKeyFile, linkPublicKey)
		if err != nil {
			return nil, err
		}
	} else {
		panic("Improbable: Only found one link PEM file.")
	}

	s.linkKey = linkPrivateKey
	blob, err := linkPublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	linkPubKeyHash := hash.Sum256(blob)
	s.log.Noticef("Server link public key hash is: %x", linkPubKeyHash[:])

	if s.cfg.Debug.GenerateOnly {
		return nil, ErrGenerateOnly
	}

	// Load and or generate mix keys.
	if s.mixKeys, err = newMixKeys(goo, cfg.SphinxGeometry); err != nil {
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

	// Initialize the PKI interface.
	if s.pki, err = NewSelfTestPKI(goo); err != nil {
		s.log.Errorf("Failed to initialize PKI client: %v", err)
		return nil, err
	}

	// Initialize the provider backend.
	if s.cfg.Server.IsProvider {
		if s.provider, err = provider.New(goo); err != nil {
			s.log.Errorf("Failed to initialize provider backend: %v", err)
			return nil, err
		}
	}

	// Initialize and start the the scheduler.
	if s.scheduler, err = scheduler.New(goo); err != nil {
		s.log.Errorf("Failed to initialize scheduler: %v", err)
		return nil, err
	}

	// Initialize and start the Sphinx workers.
	s.inboundPackets = channels.NewInfiniteChannel()
	s.cryptoWorkers = make([]*cryptoworker.Worker, 0, s.cfg.Debug.NumSphinxWorkers)
	for i := 0; i < s.cfg.Debug.NumSphinxWorkers; i++ {
		w := cryptoworker.New(goo, s.inboundPackets.Out(), i)
		s.cryptoWorkers = append(s.cryptoWorkers, w)
	}

	// Initialize the outgoing connection manager, decoy source/sink, and then
	// start the PKI worker.
	var outConn net.Conn
	s.connector, outConn = outgoing.NewSEDAFount(goo)

	// Bring the listener(s) online.
	s.listeners = make([]glue.Listener, 0, len(s.cfg.Server.Addresses))

	l, inConn := incoming.NewSEDADrain(goo, s.inboundPackets.In(), 1)
	s.listeners = append(s.listeners, l)

	// Start the periodic 1 Hz utility timer.
	s.periodic = newPeriodicTimer(s)

	if inConn == nil {
		panic("inConn is nil")
	}
	if outConn == nil {
		panic("outConn is nil")
	}

	isOk = true
	return s, nil
}

type selfTestPKI struct {
}

func NewSelfTestPKI(glue glue.Glue) (glue.PKI, error) {
	return &selfTestPKI{}, nil
}

func (p *selfTestPKI) Halt() {}

func (p *selfTestPKI) StartWorker() {}

func (p *selfTestPKI) OutgoingDestinations() map[[constants.NodeIDLength]byte]*pki.MixDescriptor {
	return nil // XXX FIXME
}

func (p *selfTestPKI) AuthenticateConnection(*wire.PeerCredentials, bool) (*pki.MixDescriptor, bool, bool) {
	return nil, false, false // XXX FIXME
}

func (p *selfTestPKI) GetRawConsensus(uint64) ([]byte, error) {
	return nil, nil // XXX FIXME
}
