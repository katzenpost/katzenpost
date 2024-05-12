package server

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"

	"gitlab.com/yawning/aez.git"
	"gopkg.in/eapache/channels.v1"

	nyquistkem "github.com/katzenpost/nyquist/kem"
	"github.com/katzenpost/nyquist/seec"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	pemkem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signpem "github.com/katzenpost/hpqc/sign/pem"

	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
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

	s.selftest = newSelfTestSenderReceiver(s)

	return s, nil
}

func newSelfTestSenderReceiver(s *Server) *selfTestSenderReceiver {
	t := &selfTestSenderReceiver{
		server: s,
	}

	go t.start()
	return t
}

type selfTestSenderReceiver struct {
	server *Server
}

func (t *selfTestSenderReceiver) start() {
	count := 1000
	packets := t.generatePackets(count)
	for i := 0; i < len(packets); i++ {
		t.sendPacket(packets[i])
	}
}

func (t *selfTestSenderReceiver) generatePackets(count int) [][]byte {
	if t.server.cfg.SphinxGeometry.KEMName == "" {
		return t.generateNIKEPackets(count)
	} else {
		return t.generateKEMPackets(count)
	}
}

func (t *selfTestSenderReceiver) sendPacket(pkt []byte) {

}

type nodeNikeParams struct {
	id         [constants.NodeIDLength]byte
	privateKey nike.PrivateKey
	publicKey  nike.PublicKey
}

func newKemNode(mykem kem.Scheme) *nodeKemParams {
	n := new(nodeKemParams)
	_, err := rand.Reader.Read(n.id[:])
	if err != nil {
		panic(err)
	}
	n.publicKey, n.privateKey, err = mykem.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	return n
}

type nodeKemParams struct {
	id         [constants.NodeIDLength]byte
	privateKey kem.PrivateKey
	publicKey  kem.PublicKey
}

func newNikeNode(mynike nike.Scheme) *nodeNikeParams {
	n := new(nodeNikeParams)
	_, err := rand.Reader.Read(n.id[:])
	if err != nil {
		panic(err)
	}
	n.publicKey, n.privateKey, err = mynike.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	return n
}

func newNikePathVector(mynike nike.Scheme, nodes []*nodeNikeParams, nrHops int, isSURB bool) []*sphinx.PathHop {
	const delayBase = 0xdeadbabe

	// Assemble the path vector.
	path := make([]*sphinx.PathHop, nrHops)
	for i := range path {
		path[i] = new(sphinx.PathHop)
		copy(path[i].ID[:], nodes[i].id[:])
		path[i].NIKEPublicKey = nodes[i].publicKey
		if i < nrHops-1 {
			// Non-terminal hop, add the delay.
			delay := new(commands.NodeDelay)
			delay.Delay = delayBase * uint32(i+1)
			path[i].Commands = append(path[i].Commands, delay)
		} else {
			// Terminal hop, add the recipient.
			recipient := new(commands.Recipient)
			_, err := rand.Reader.Read(recipient.ID[:])
			if err != nil {
				panic(err)
			}
			path[i].Commands = append(path[i].Commands, recipient)

			// This is a SURB, add a surb_reply.
			if isSURB {
				surbReply := new(commands.SURBReply)
				_, err := rand.Reader.Read(surbReply.ID[:])
				if err != nil {
					panic(err)
				}
				path[i].Commands = append(path[i].Commands, surbReply)
			}
		}
	}
	return path
}

func newKemPathVector(mykem kem.Scheme, nodes []*nodeKemParams, nrHops int, isSURB bool) []*sphinx.PathHop {
	const delayBase = 0xdeadbabe

	// Assemble the path vector.
	path := make([]*sphinx.PathHop, nrHops)
	for i := range path {
		path[i] = new(sphinx.PathHop)
		copy(path[i].ID[:], nodes[i].id[:])
		path[i].KEMPublicKey = nodes[i].publicKey
		if i < nrHops-1 {
			// Non-terminal hop, add the delay.
			delay := new(commands.NodeDelay)
			delay.Delay = delayBase * uint32(i+1)
			path[i].Commands = append(path[i].Commands, delay)
		} else {
			// Terminal hop, add the recipient.
			recipient := new(commands.Recipient)
			_, err := rand.Reader.Read(recipient.ID[:])
			if err != nil {
				panic(err)
			}
			path[i].Commands = append(path[i].Commands, recipient)

			// This is a SURB, add a surb_reply.
			if isSURB {
				surbReply := new(commands.SURBReply)
				_, err := rand.Reader.Read(surbReply.ID[:])
				if err != nil {
					panic(err)
				}
				path[i].Commands = append(path[i].Commands, surbReply)
			}
		}
	}
	return path
}

func (t *selfTestSenderReceiver) generateNIKEPackets(count int) [][]byte {
	packets := make([][]byte, count)
	for i := 0; i < count; i++ {
		packet := t.generateNIKEPacket()
		packets[i] = packet
	}
	return packets
}

func (t *selfTestSenderReceiver) generateNIKEPacket() []byte {
	epoch, _, _ := epochtime.Now()
	mixkeys := t.server.cryptoWorkers[0].MixKeys()
	mixkey := mixkeys[epoch]

	nodes := make([]*nodeNikeParams, t.server.cfg.SphinxGeometry.NrHops)
	mixpubkey, _ := mixkey.PublicKey()
	mixprivkey := mixkey.PrivateKey().(nike.PrivateKey)
	nodes[0] = &nodeNikeParams{
		id:         hash.Sum256From(t.server.identityPublicKey),
		privateKey: mixprivkey,
		publicKey:  mixpubkey,
	}

	mynike := nikeschemes.ByName(t.server.cfg.SphinxGeometry.NIKEName)
	if mynike == nil {
		panic("nike scheme is nil")
	}

	for i := 1; i < len(nodes); i++ {
		nodes[i] = newNikeNode(mynike)
	}

	path := newNikePathVector(mynike, nodes, t.server.cfg.SphinxGeometry.NrHops, true)

	payload := make([]byte, t.server.cfg.SphinxGeometry.ForwardPayloadLength)

	mysphinx := sphinx.NewSphinx(t.server.cfg.SphinxGeometry)
	pkt, err := mysphinx.NewPacket(rand.Reader, path, payload)
	if err != nil {
		panic(err)
	}
	return pkt
}

func (t *selfTestSenderReceiver) generateKEMPackets(count int) [][]byte {
	packets := make([][]byte, count)
	for i := 0; i < count; i++ {
		packet := t.generateKEMPacket()
		packets[i] = packet
	}
	return packets
}

func (t *selfTestSenderReceiver) generateKEMPacket() []byte {
	epoch, _, _ := epochtime.Now()
	mixkeys := t.server.cryptoWorkers[0].MixKeys()
	mixkey := mixkeys[epoch]

	nodes := make([]*nodeKemParams, t.server.cfg.SphinxGeometry.NrHops)
	_, mixpubkey := mixkey.PublicKey()
	mixprivkey := mixkey.PrivateKey().(kem.PrivateKey)
	nodes[0] = &nodeKemParams{
		id:         hash.Sum256From(t.server.identityPublicKey),
		privateKey: mixprivkey,
		publicKey:  mixpubkey,
	}

	mykem := kemschemes.ByName(t.server.cfg.SphinxGeometry.KEMName)
	if mykem == nil {
		panic("kem scheme is nil")
	}

	for i := 1; i < len(nodes); i++ {
		nodes[i] = newKemNode(mykem)
	}

	path := newKemPathVector(mykem, nodes, t.server.cfg.SphinxGeometry.NrHops, true)

	payload := make([]byte, t.server.cfg.SphinxGeometry.ForwardPayloadLength)

	mysphinx := sphinx.NewSphinx(t.server.cfg.SphinxGeometry)
	pkt, err := mysphinx.NewPacket(rand.Reader, path, payload)
	if err != nil {
		panic(err)
	}
	return pkt
}

type privateDescriptor struct {
	identityPrivKey sign.PrivateKey
	linkPrivKey     kem.PrivateKey
}

type descriptor struct {
	pubDesc         *pki.MixDescriptor
	identityPrivKey sign.PrivateKey
	linkPrivKey     kem.PrivateKey
}

type selfTestPKI struct {
	outgoing map[[constants.NodeIDLength]byte]*pki.MixDescriptor
	incoming map[[constants.NodeIDLength]byte]*pki.MixDescriptor
	privDesc map[[constants.NodeIDLength]byte]*privateDescriptor

	outDesc *pki.MixDescriptor
	inDesc  *pki.MixDescriptor

	geo     *geo.Geometry
	wireKEM string
}

func NewSelfTestPKI(glue glue.Glue) (glue.PKI, error) {
	cfg := glue.Config()

	p := &selfTestPKI{
		outgoing: make(map[[constants.NodeIDLength]byte]*pki.MixDescriptor),
		incoming: make(map[[constants.NodeIDLength]byte]*pki.MixDescriptor),
		privDesc: make(map[[constants.NodeIDLength]byte]*privateDescriptor),
		geo:      cfg.SphinxGeometry,
		wireKEM:  cfg.Server.WireKEM,
	}

	p.init()

	return p, nil
}

func (p *selfTestPKI) init() {
	privDesc1, pubDesc1, err := p.generateDesc()
	if err != nil {
		panic(err)
	}

	privDesc2, pubDesc2, err := p.generateDesc()
	if err != nil {
		panic(err)
	}

	id1 := hash.Sum256(pubDesc1.IdentityKey)
	id2 := hash.Sum256(pubDesc2.IdentityKey)
	p.outgoing[id1] = pubDesc1
	p.incoming[id2] = pubDesc2
	p.outDesc = pubDesc1
	p.inDesc = pubDesc2

	p.privDesc[id1] = privDesc1
	p.privDesc[id2] = privDesc2
}

func (p *selfTestPKI) generateDesc() (*privateDescriptor, *pki.MixDescriptor, error) {
	epoch, _, _ := epochtime.Now()
	identityPubKey, identityPrivKey, err := cert.Scheme.GenerateKey()
	if err != nil {
		return nil, nil, err
	}

	idkeybytes, err := identityPubKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	kemscheme := schemes.ByName(p.wireKEM)
	if kemscheme == nil {
		return nil, nil, errors.New("kem scheme is nil")
	}

	linkpubkey, linkprivkey, err := kemscheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	linkKeybytes, err := linkpubkey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	desc := &pki.MixDescriptor{
		Name:        "mix0",
		Epoch:       epoch,
		IdentityKey: idkeybytes,
		LinkKey:     linkKeybytes,
	}

	return &privateDescriptor{
		identityPrivKey: identityPrivKey,
		linkPrivKey:     linkprivkey,
	}, desc, nil
}

func (p *selfTestPKI) Halt() {}

func (p *selfTestPKI) StartWorker() {}

func (p *selfTestPKI) OutgoingDestinations() map[[constants.NodeIDLength]byte]*pki.MixDescriptor {
	return p.outgoing
}

func (p *selfTestPKI) AuthenticateConnection(c *wire.PeerCredentials, isOutgoing bool) (*pki.MixDescriptor, bool, bool) {
	if isOutgoing {
		return p.outDesc, true, true
	} else {
		return p.inDesc, true, true
	}
	return nil, false, false // not reached
}

func (p *selfTestPKI) GetRawConsensus(uint64) ([]byte, error) {
	return nil, nil
}
