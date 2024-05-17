// state_test.go - Voting authority state machine tests.
// Copyright (C) 2018  David Stainton
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

package server

import (
	"bytes"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signpem "github.com/katzenpost/hpqc/sign/pem"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	sConfig "github.com/katzenpost/katzenpost/server/config"
)

var testingSchemeName = "xwing"
var testingScheme = schemes.ByName(testingSchemeName)

var sphinxGeometry = geo.GeometryFromUserForwardPayloadLength(
	x25519.Scheme(rand.Reader),
	2000,
	true,
	5,
)

func TestVote(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	// instantiate states
	authNum := 3
	stateAuthority := make([]*state, authNum)
	votingEpoch, _, _ := epochtime.Now()
	votingEpoch += 5
	parameters := &config.Parameters{
		SendRatePerMinute: 100, Mu: 0.001, MuMaxDelay: 9000,
		LambdaP: 0.002, LambdaPMaxDelay: 9000,
		LambdaL: 0.0005, LambdaLMaxDelay: 9000,
		LambdaD: 0.0005, LambdaDMaxDelay: 9000,
		LambdaM: 0.2, LambdaMMaxDelay: 9000,
	}

	peerKeys, authCfgs, err := genVotingAuthoritiesCfg(parameters, authNum)
	require.NoError(err)

	reverseHash := make(map[[publicKeyHashSize]byte]sign.PublicKey)

	// set up authorities from configuration
	for i := 0; i < authNum; i++ {
		st := new(state)
		st.votingEpoch = votingEpoch
		cfg := authCfgs[i]
		st.verifiers = make(map[[publicKeyHashSize]byte]sign.PublicKey)
		for j, _ := range peerKeys {
			st.verifiers[hash.Sum256From(peerKeys[j].idPubKey)] = sign.PublicKey(peerKeys[j].idPubKey)
		}
		st.threshold = len(st.verifiers)/2 + 1
		st.dissenters = len(cfg.Authorities)/2 - 1

		s := &Server{
			cfg:                cfg,
			identityPrivateKey: peerKeys[i].idKey,
			identityPublicKey:  peerKeys[i].idPubKey,
			fatalErrCh:         make(chan error),
			haltedCh:           make(chan interface{}),
		}
		reverseHash[hash.Sum256From(peerKeys[i].idPubKey)] = peerKeys[i].idPubKey

		go func() {
			for {
				select {
				case err := <-s.fatalErrCh:
					require.NoError(err)
				case _, ok := <-s.haltedCh:
					if !ok {
						return
					}
				}
			}
		}()
		st.s = s
		s.logBackend, err = log.New(cfg.Logging.File, s.cfg.Logging.Level, s.cfg.Logging.Disable)
		st.log = s.logBackend.GetLogger(fmt.Sprintf("state%d", i))
		if err == nil {
			s.log = s.logBackend.GetLogger("authority")
		}

		st.documents = make(map[uint64]*pki.Document)
		st.myconsensus = make(map[uint64]*pki.Document)
		st.descriptors = make(map[uint64]map[[hash.HashSize]byte]*pki.MixDescriptor)
		st.votes = make(map[uint64]map[[hash.HashSize]byte]*pki.Document)
		st.votes[votingEpoch] = make(map[[hash.HashSize]byte]*pki.Document)
		st.certificates = make(map[uint64]map[[hash.HashSize]byte]*pki.Document)
		st.certificates[st.votingEpoch] = make(map[[hash.HashSize]byte]*pki.Document)
		st.commits = make(map[uint64]map[[hash.HashSize]byte][]byte)
		st.reveals = make(map[uint64]map[[hash.HashSize]byte][]byte)
		st.signatures = make(map[uint64]map[[hash.HashSize]byte]*cert.Signature)
		st.signatures[st.votingEpoch] = make(map[[hash.HashSize]byte]*cert.Signature)
		st.reveals[st.votingEpoch] = make(map[[hash.HashSize]byte][]byte)
		st.reverseHash = make(map[[publicKeyHashSize]byte]sign.PublicKey)
		stateAuthority[i] = st
		tmpDir, err := os.MkdirTemp("", cfg.Server.Identifier)
		require.NoError(err)
		dbPath := filepath.Join(tmpDir, "persistance.db")
		db, err := bolt.Open(dbPath, 0600, nil)
		require.NoError(err)
		st.db = db
		// create all the db cruft
		err = st.restorePersistence()
		require.NoError(err)
	}

	// create a voting PKI configuration
	authorities := make([]*config.Authority, 0)
	for i, aCfg := range authCfgs {
		require.NoError(err)
		auth := &config.Authority{Addresses: aCfg.Server.Addresses,
			WireKEMScheme:     testingSchemeName,
			IdentityPublicKey: peerKeys[i].idPubKey,
			LinkPublicKey:     peerKeys[i].linkKey.Public(),
		}
		if len(aCfg.Server.Addresses) == 0 {
			panic("wtf")
		}
		authorities = append(authorities, auth)
	}
	votingPKI := &sConfig.PKI{
		Voting: &sConfig.Voting{
			Authorities: authorities,
		},
	}

	// generate mixes
	n := 3 * 2 // 3 layer, 2 nodes per layer
	m := 2     // 2 providers
	idKeys := make([]*identityKey, 0)
	mixCfgs := make([]*sConfig.Config, 0)
	port := uint16(30000)
	for i := 0; i < n; i++ {
		idKey, c, err := genMixConfig(fmt.Sprintf("node-%d", i), votingPKI, port)
		require.NoError(err)
		mixCfgs = append(mixCfgs, c)
		idKeys = append(idKeys, idKey)
		port++
		reverseHash[hash.Sum256From(idKey.pubKey)] = idKey.pubKey
	}

	// generate a Topology section
	topology := config.Topology{Layers: make([]config.Layer, 3)}
	topology.Layers[0].Nodes = []config.Node{config.Node{IdentityPublicKeyPem: idKeys[0].identityPublicKeyPem},
		config.Node{IdentityPublicKeyPem: idKeys[1].identityPublicKeyPem}}
	topology.Layers[1].Nodes = []config.Node{config.Node{IdentityPublicKeyPem: idKeys[2].identityPublicKeyPem},
		config.Node{IdentityPublicKeyPem: idKeys[3].identityPublicKeyPem}}
	topology.Layers[2].Nodes = []config.Node{config.Node{IdentityPublicKeyPem: idKeys[4].identityPublicKeyPem},
		config.Node{IdentityPublicKeyPem: idKeys[5].identityPublicKeyPem}}

	// generate a Topology section
	authCfgs[0].Topology = &topology
	authCfgs[1].Topology = &topology
	authCfgs[2].Topology = &topology

	// generate gateways
	for i := 0; i < m; i++ {
		idKey, c, err := genGatewayConfig(fmt.Sprintf("gateway-%d", i), votingPKI, port)
		require.NoError(err)
		mixCfgs = append(mixCfgs, c)
		idKeys = append(idKeys, idKey)
		port++
		reverseHash[hash.Sum256From(idKey.pubKey)] = idKey.pubKey
	}
	// generate serviceNodes
	for i := 0; i < m; i++ {
		idKey, c, err := genServiceNodeConfig(fmt.Sprintf("serviceNode-%d", i), votingPKI, port)
		require.NoError(err)
		mixCfgs = append(mixCfgs, c)
		idKeys = append(idKeys, idKey)
		port++
		reverseHash[hash.Sum256From(idKey.pubKey)] = idKey.pubKey
	}

	for i := 0; i < len(stateAuthority); i++ {
		stateAuthority[i].reverseHash = reverseHash
	}

	// post descriptors from nodes
	mixDescs := make([]*pki.MixDescriptor, 0)
	gatewayDescs := make([]*pki.MixDescriptor, 0)
	serviceDescs := make([]*pki.MixDescriptor, 0)
	for i := 0; i < len(mixCfgs); i++ {
		mkeys := genMixKeys(votingEpoch)
		addr := make(map[string][]string)
		addr[pki.TransportTCPv4] = []string{"127.0.0.1:1234"}
		linkPubKey, _, err := testingScheme.GenerateKeyPair()
		linkBlob, err := linkPubKey.MarshalBinary()
		if err != nil {
			panic(err)
		}
		idkeyblob, err := idKeys[i].pubKey.MarshalBinary()
		require.NoError(err)

		desc := &pki.MixDescriptor{
			Name:          mixCfgs[i].Server.Identifier,
			Epoch:         votingEpoch,
			IdentityKey:   idkeyblob,
			LinkKey:       linkBlob,
			MixKeys:       mkeys,
			IsGatewayNode: mixCfgs[i].Server.IsGatewayNode,
			IsServiceNode: mixCfgs[i].Server.IsServiceNode,
			Addresses:     addr,
		}

		err = pki.IsDescriptorWellFormed(desc, votingEpoch)
		require.NoError(err)

		if mixCfgs[i].Server.IsServiceNode {
			serviceDescs = append(serviceDescs, desc)
		} else if mixCfgs[i].Server.IsGatewayNode {
			gatewayDescs = append(gatewayDescs, desc)
		} else {
			mixDescs = append(mixDescs, desc)
		}
	}

	// create and exchange signed commits and reveals
	commits := make(map[uint64]map[[hash.HashSize]byte][]byte)
	commits[votingEpoch] = make(map[[hash.HashSize]byte][]byte)

	// exchange commit and create reveals
	for _, s := range stateAuthority {
		reveals := make(map[uint64]map[[hash.HashSize]byte][]byte)
		reveals[votingEpoch] = make(map[[hash.HashSize]byte][]byte)

		srv := new(pki.SharedRandom)
		commit, err := srv.Commit(votingEpoch)
		require.NoError(err)
		signedCommit, err := cert.Sign(s.s.identityPrivateKey, s.s.identityPublicKey, commit, votingEpoch+1)
		require.NoError(err)
		commits[votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = signedCommit
		s.commits = commits

		reveal := srv.Reveal()
		signedReveal, err := cert.Sign(s.s.identityPrivateKey, s.s.identityPublicKey, reveal, votingEpoch+1)
		require.NoError(err)
		reveals[votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = signedReveal
		s.reveals = reveals
	}

	// populate the authorities with the descriptors
	for _, s := range stateAuthority {
		s.descriptors[votingEpoch] = make(map[[hash.HashSize]byte]*pki.MixDescriptor)
		s.authorizedMixes = make(map[[hash.HashSize]byte]bool)
		s.authorizedGatewayNodes = make(map[[hash.HashSize]byte]string)
		s.authorizedServiceNodes = make(map[[hash.HashSize]byte]string)
		for _, d := range mixDescs {
			s.descriptors[votingEpoch][hash.Sum256(d.IdentityKey)] = d
			s.authorizedMixes[hash.Sum256(d.IdentityKey)] = true
		}
		for _, d := range gatewayDescs {
			s.descriptors[votingEpoch][hash.Sum256(d.IdentityKey)] = d
			s.authorizedGatewayNodes[hash.Sum256(d.IdentityKey)] = d.Name
		}
		for _, d := range serviceDescs {
			s.descriptors[votingEpoch][hash.Sum256(d.IdentityKey)] = d
			s.authorizedServiceNodes[hash.Sum256(d.IdentityKey)] = d.Name
		}
	}

	// exchange votes
	for i, s := range stateAuthority {
		s.votingEpoch = votingEpoch
		s.genesisEpoch = s.votingEpoch
		myVote, err := s.getVote(s.votingEpoch)
		require.Equal(len(myVote.Signatures), 1)
		require.NoError(err)
		require.NotNil(myVote)
		raw, err := myVote.MarshalBinary()
		require.NoError(err)
		_, err = pki.ParseDocument(raw)
		require.NoError(err)
		s.state = stateAcceptVote
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.votes[s.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = myVote
		}
	}

	// exchange reveals
	for i, s := range stateAuthority {
		s.state = stateAcceptReveal
		c := s.reveal(s.votingEpoch)
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.reveals[a.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = c
			t.Logf("%s sent %s reveal", authCfgs[i].Server.Identifier, authCfgs[j].Server.Identifier)
		}

	}

	// exchange certificates
	for i, s := range stateAuthority {
		s.Lock()
		s.state = stateAcceptCert
		myCertificate, err := s.getCertificate(s.votingEpoch)
		require.NoError(err)
		_, err = pki.SignDocument(s.s.identityPrivateKey, s.s.identityPublicKey, myCertificate)
		require.NoError(err)
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.certificates[s.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = myCertificate
		}
		s.Unlock()
	}

	// produced a consensus document signed by each authority
	for _, s := range stateAuthority {
		s.Lock()
		_, err := s.getMyConsensus(s.votingEpoch)
		s.Unlock()
		require.NoError(err)
	}

	// exchange signatures over the consensus
	for i, s := range stateAuthority {
		s.state = stateAcceptSignature
		id := hash.Sum256From(s.s.identityPublicKey)
		mySignature, ok := s.myconsensus[s.votingEpoch].Signatures[id]
		require.True(ok)

		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.signatures[s.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = &mySignature
		}
	}
	// verify that each authority produced an identital consensus
	consensusHash := ""
	for _, s := range stateAuthority {
		s.Lock()
		doc, err := s.getThresholdConsensus(s.votingEpoch)
		s.Unlock()
		require.NoError(err)
		hash := doc.Sum256()
		if consensusHash == "" {
			consensusHash = string(hash[:])
		} else {
			require.Equal(consensusHash, string(hash[:]))
		}
	}
}

type peerKeys struct {
	linkKey  kem.PrivateKey
	idKey    sign.PrivateKey
	idPubKey sign.PublicKey
	datadir  string
}

func genVotingAuthoritiesCfg(parameters *config.Parameters, numAuthorities int) ([]peerKeys, []*config.Config, error) {
	configs := []*config.Config{}
	basePort := 30000
	lastPort := basePort + 1

	myPeerKeys := make([]peerKeys, numAuthorities)

	// initial generation of key material for each authority
	peersMap := make(map[[hash.HashSize]byte]*config.Authority)
	for i := 0; i < numAuthorities; i++ {
		cfg := new(config.Config)
		cfg.SphinxGeometry = sphinxGeometry
		cfg.Logging = &config.Logging{Disable: false, File: "", Level: "DEBUG"}
		cfg.Parameters = parameters

		datadir, err := os.MkdirTemp("", fmt.Sprintf("auth_%d", i))
		if err != nil {
			panic(err)
		}

		cfg.Server = new(config.Server)
		cfg.Server.Identifier = fmt.Sprintf("authority-%v", i)
		cfg.Server.Addresses = []string{fmt.Sprintf("127.0.0.1:%d", lastPort)}
		cfg.Server.DataDir = datadir
		lastPort += 1

		scheme := testingScheme
		linkPubKey, linkKey, err := scheme.GenerateKeyPair()
		if err != nil {
			return nil, nil, err
		}
		idPubKey, idKey, err := cert.Scheme.GenerateKey()
		if err != nil {
			return nil, nil, err
		}

		myPeerKeys[i] = peerKeys{
			linkKey:  linkKey,
			idKey:    idKey,
			idPubKey: idPubKey,
			datadir:  datadir,
		}

		cfg.Debug = &config.Debug{
			Layers:           3,
			MinNodesPerLayer: 1,
			GenerateOnly:     false,
		}
		configs = append(configs, cfg)
		authorityPeer := &config.Authority{
			IdentityPublicKey: idPubKey,
			LinkPublicKey:     linkPubKey,
			Addresses:         cfg.Server.Addresses,
		}
		peersMap[hash.Sum256From(idPubKey)] = authorityPeer
	}

	// tell each authority about it's peers
	for i := 0; i < numAuthorities; i++ {
		peers := []*config.Authority{}
		for id, peer := range peersMap {
			idHash := hash.Sum256From(myPeerKeys[i].idPubKey)
			if !bytes.Equal(id[:], idHash[:]) {
				peers = append(peers, peer)
			}
		}
		configs[i].Authorities = peers
	}
	return myPeerKeys, configs, nil
}

func genGatewayConfig(name string, pki *sConfig.PKI, port uint16) (*identityKey, *sConfig.Config, error) {
	const serverLogFile = ""

	cfg := new(sConfig.Config)

	cfg.SphinxGeometry = sphinxGeometry

	// Server section.
	cfg.Server = new(sConfig.Server)
	cfg.Server.WireKEM = testingSchemeName
	cfg.Server.Identifier = name
	cfg.Server.Addresses = []string{fmt.Sprintf("127.0.0.1:%d", port)}
	cfg.Server.AltAddresses = map[string][]string{
		"TCP": []string{fmt.Sprintf("localhost:%d", port)},
	}

	datadir, err := os.MkdirTemp("", fmt.Sprintf("provider_%s", name))
	if err != nil {
		panic(err)
	}

	cfg.Server.DataDir = datadir
	cfg.Server.IsGatewayNode = true
	cfg.Server.IsServiceNode = false

	// Debug section.
	cfg.Debug = new(sConfig.Debug)

	// Generate keys
	idPubKey, idKey, err := cert.Scheme.GenerateKey()
	if err != nil {
		panic(err)
	}

	scheme := testingScheme
	linkPubKey, linkKey, err := scheme.GenerateKeyPair()
	linkPublicKeyPem := "link.public.pem"

	idprivkeypem := filepath.Join(datadir, "identity.private.pem")

	err = signpem.PrivateKeyToFile(idprivkeypem, idKey)
	if err != nil {
		return nil, nil, err
	}

	err = signpem.PublicKeyToFile(filepath.Join(datadir, "identity.public.pem"), idPubKey)
	if err != nil {
		return nil, nil, err
	}

	err = kempem.PrivateKeyToFile(filepath.Join(datadir, "link.private.pem"), linkKey)
	if err != nil {
		return nil, nil, err
	}

	err = kempem.PublicKeyToFile(filepath.Join(datadir, linkPublicKeyPem), linkPubKey)
	if err != nil {
		return nil, nil, err
	}

	// PKI section.
	cfg.PKI = pki

	cfg.Gateway = new(sConfig.Gateway)
	err = cfg.FixupAndValidate()
	if err != nil {
		return nil, nil, err
	}
	return &identityKey{
		publicPemFile:         filepath.Join(datadir, "identity.public.pem"),
		privatePemFile:        filepath.Join(datadir, "identity.private.pem"),
		identityPrivateKeyPem: idprivkeypem,
		privKey:               idKey,
		pubKey:                idPubKey,
	}, cfg, nil
}

func genServiceNodeConfig(name string, pki *sConfig.PKI, port uint16) (*identityKey, *sConfig.Config, error) {
	const serverLogFile = ""

	cfg := new(sConfig.Config)

	cfg.SphinxGeometry = sphinxGeometry

	// Server section.
	cfg.Server = new(sConfig.Server)
	cfg.Server.WireKEM = testingSchemeName
	cfg.Server.Identifier = name
	cfg.Server.Addresses = []string{fmt.Sprintf("127.0.0.1:%d", port)}
	cfg.Server.AltAddresses = map[string][]string{
		"TCP": []string{fmt.Sprintf("localhost:%d", port)},
	}

	datadir, err := os.MkdirTemp("", fmt.Sprintf("provider_%s", name))
	if err != nil {
		panic(err)
	}

	cfg.Server.DataDir = datadir
	cfg.Server.IsGatewayNode = false
	cfg.Server.IsServiceNode = true

	// Debug section.
	cfg.Debug = new(sConfig.Debug)

	// Generate keys
	idPubKey, idKey, err := cert.Scheme.GenerateKey()
	if err != nil {
		panic(err)
	}
	scheme := testingScheme
	linkPubKey, linkKey, err := scheme.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	linkPublicKeyPem := "link.public.pem"

	idprivkeypem := filepath.Join(datadir, "identity.private.pem")

	err = signpem.PrivateKeyToFile(idprivkeypem, idKey)
	if err != nil {
		return nil, nil, err
	}

	err = signpem.PublicKeyToFile(filepath.Join(datadir, "identity.public.pem"), idPubKey)
	if err != nil {
		return nil, nil, err
	}

	err = kempem.PrivateKeyToFile(filepath.Join(datadir, "link.private.pem"), linkKey)
	if err != nil {
		return nil, nil, err
	}

	err = kempem.PublicKeyToFile(filepath.Join(datadir, linkPublicKeyPem), linkPubKey)
	if err != nil {
		return nil, nil, err
	}

	// PKI section.
	cfg.PKI = pki

	cfg.ServiceNode = new(sConfig.ServiceNode)

	echoCfg := new(sConfig.Kaetzchen)
	echoCfg.Capability = "echo"
	echoCfg.Endpoint = "+echo"
	cfg.ServiceNode.Kaetzchen = append(cfg.ServiceNode.Kaetzchen, echoCfg)
	err = cfg.FixupAndValidate()
	if err != nil {
		return nil, nil, err
	}
	return &identityKey{
		publicPemFile:         filepath.Join(datadir, "identity.public.pem"),
		privatePemFile:        filepath.Join(datadir, "identity.private.pem"),
		identityPrivateKeyPem: idprivkeypem,
		privKey:               idKey,
		pubKey:                idPubKey,
	}, cfg, nil
}

type identityKey struct {
	publicPemFile         string
	privatePemFile        string
	identityPrivateKeyPem string
	identityPublicKeyPem  string
	privKey               sign.PrivateKey
	pubKey                sign.PublicKey
}

func genMixConfig(name string, pki *sConfig.PKI, port uint16) (*identityKey, *sConfig.Config, error) {
	const serverLogFile = ""

	cfg := new(sConfig.Config)

	cfg.SphinxGeometry = sphinxGeometry

	// Server section.
	cfg.Server = new(sConfig.Server)
	cfg.Server.WireKEM = testingSchemeName
	cfg.Server.Identifier = name
	cfg.Server.Addresses = []string{fmt.Sprintf("127.0.0.1:%d", port)}
	cfg.Server.IsGatewayNode = false
	cfg.Server.IsServiceNode = false

	datadir, err := os.MkdirTemp("", fmt.Sprintf("mix_%s", name))
	if err != nil {
		panic(err)
	}

	cfg.Server.DataDir = datadir

	// Debug section.
	cfg.Debug = new(sConfig.Debug)

	// Generate keys
	idPubKey, idKey, err := cert.Scheme.GenerateKey()
	if err != nil {
		return nil, nil, err
	}

	scheme := testingScheme
	linkPubKey, linkKey, err := scheme.GenerateKeyPair()
	linkPublicKeyPem := "link.public.pem"

	idprivkeypem := filepath.Join(datadir, "identity.private.pem")
	idpubkeypem := filepath.Join(datadir, "identity.public.pem")

	err = signpem.PrivateKeyToFile(idprivkeypem, idKey)
	if err != nil {
		return nil, nil, err
	}

	err = signpem.PublicKeyToFile(idpubkeypem, idPubKey)
	if err != nil {
		return nil, nil, err
	}

	err = kempem.PrivateKeyToFile(filepath.Join(datadir, "link.private.pem"), linkKey)
	if err != nil {
		return nil, nil, err
	}

	err = kempem.PublicKeyToFile(filepath.Join(datadir, linkPublicKeyPem), linkPubKey)
	if err != nil {
		return nil, nil, err
	}

	// PKI section.
	cfg.PKI = pki

	// Logging section.
	cfg.Logging = new(sConfig.Logging)
	cfg.Logging.File = serverLogFile
	cfg.Logging.Level = "DEBUG"
	err = cfg.FixupAndValidate()
	if err != nil {
		return nil, nil, err
	}
	return &identityKey{
		publicPemFile:         filepath.Join(datadir, "identity.public.pem"),
		privatePemFile:        filepath.Join(datadir, "identity.private.pem"),
		identityPrivateKeyPem: idprivkeypem,
		identityPublicKeyPem:  idpubkeypem,
		privKey:               idKey,
		pubKey:                idPubKey,
	}, cfg, nil
}

// create epoch keys
func genMixKeys(votingEpoch uint64) map[uint64][]byte {
	mixKeys := make(map[uint64][]byte)
	for i := votingEpoch; i < votingEpoch+2; i++ {
		pubkey, _, err := x25519.Scheme(rand.Reader).GenerateKeyPairFromEntropy(rand.Reader)
		if err != nil {
			panic(err)
		}

		mixKeys[i] = pubkey.Bytes()
	}
	return mixKeys
}

func init() {
	go func() {
		http.ListenAndServe("localhost:8081", nil)
	}()
	runtime.SetMutexProfileFraction(1)
	runtime.SetBlockProfileRate(1)
}
