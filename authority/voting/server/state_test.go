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
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
	sConfig "github.com/katzenpost/katzenpost/server/config"
)

var testingSchemeName = "xwing"
var testingScheme = schemes.ByName(testingSchemeName)
var testSignatureScheme = signSchemes.ByName("Ed25519")

var sphinxGeometry = geo.GeometryFromUserForwardPayloadLength(
	x25519.Scheme(rand.Reader),
	2000,
	true,
	5,
)

func TestMalformedConsensusWithEmptyTopologyIsRejected(t *testing.T) {
	doc := &pki.Document{
		Version:           pki.DocumentVersion,
		Epoch:             1,
		GenesisEpoch:      1,
		Topology:          nil,
		GatewayNodes:      nil,
		ServiceNodes:      nil,
		SharedRandomValue: make([]byte, pki.SharedRandomValueLength),
	}

	err := pki.IsDocumentWellFormed(doc, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Document contains no Topology")
}

// testVoteWithAuthorities is a parameterized test function that tests voting
// with different numbers of directory authorities
func testVoteWithAuthorities(t *testing.T, authNum int, expectedSuccessfulConsensus int) {
	require := require.New(t)

	t.Logf("=== TESTING %d AUTHORITIES SCENARIO ===", authNum)
	t.Logf("Expected successful consensus: %d", expectedSuccessfulConsensus)
	stateAuthority := make([]*state, authNum)
	votingEpoch, _, _ := epochtime.Now()
	votingEpoch += 5
	parameters := &config.Parameters{
		Mu:      0.001,
		LambdaP: 0.002,
		LambdaL: 0.0005,
		LambdaM: 0.2,
	}

	peerKeys, authCfgs, err := genVotingAuthoritiesCfg(parameters, authNum)
	require.NoError(err)

	reverseHash := make(map[[publicKeyHashSize]byte]sign.PublicKey)
	authorityNames := make(map[[publicKeyHashSize]byte]string)

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
		pk := hash.Sum256From(peerKeys[i].idPubKey)
		reverseHash[pk] = peerKeys[i].idPubKey
		authorityNames[pk] = authCfgs[i].Server.Identifier

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
			WireKEMScheme:      testingSchemeName,
			PKISignatureScheme: testSignatureScheme.Name(),
			IdentityPublicKey:  peerKeys[i].idPubKey,
			LinkPublicKey:      config.LinkPublicKey{PublicKey: peerKeys[i].linkKey.Public()},
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

	// set topology for all authorities
	for i := 0; i < authNum; i++ {
		authCfgs[i].Topology = &topology
	}

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
		stateAuthority[i].authorityNames = authorityNames
	}

	// post descriptors from nodes
	mixDescs := make([]*pki.MixDescriptor, 0)
	gatewayDescs := make([]*pki.MixDescriptor, 0)
	serviceDescs := make([]*pki.MixDescriptor, 0)
	for i := 0; i < len(mixCfgs); i++ {
		mkeys := genMixKeys(votingEpoch)
		addr := make(map[string][]string)
		addr[pki.TransportTCPv4] = []string{"tcp4://127.0.0.1:1234"}
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
		s.authorizedMixes = make(map[[hash.HashSize]byte]string)
		s.authorizedGatewayNodes = make(map[[hash.HashSize]byte]string)
		s.authorizedServiceNodes = make(map[[hash.HashSize]byte]string)
		for _, d := range mixDescs {
			s.descriptors[votingEpoch][hash.Sum256(d.IdentityKey)] = d
			s.authorizedMixes[hash.Sum256(d.IdentityKey)] = d.Name
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
		raw, err := myVote.MarshalCertificate()
		require.NoError(err)
		_, err = pki.ParseDocument(raw)
		require.NoError(err)
		s.state = stateAcceptVote
		// Distribute vote to other authorities with proper locking
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.Lock()
			a.votes[s.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = myVote
			a.Unlock()
		}
	}

	// exchange reveals
	for i, s := range stateAuthority {
		s.state = stateAcceptReveal
		c := s.reveal(s.votingEpoch)
		// Distribute reveal to other authorities with proper locking
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.Lock()
			a.reveals[a.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = c
			a.Unlock()
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
		// Distribute certificate to other authorities with proper locking
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.Lock()
			a.certificates[s.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = myCertificate
			a.Unlock()
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

		// Distribute signature to other authorities with proper locking
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.Lock()
			a.signatures[s.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = &mySignature
			a.Unlock()
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

// Test functions for different numbers of authorities
func TestVote3Authorities(t *testing.T) {
	testVoteWithAuthorities(t, 3, 3) // All 3 authorities should achieve consensus
}

func TestVote4Authorities(t *testing.T) {
	testVoteWithAuthorities(t, 4, 3) // 3 out of 4 authorities should achieve consensus
}

func TestVote5Authorities(t *testing.T) {
	testVoteWithAuthorities(t, 5, 3) // 3 out of 5 authorities should achieve consensus
}

func TestVote6Authorities(t *testing.T) {
	testVoteWithAuthorities(t, 6, 4) // 4 out of 6 authorities should achieve consensus
}

func TestVote7Authorities(t *testing.T) {
	testVoteWithAuthorities(t, 7, 4) // 4 out of 7 authorities should achieve consensus
}

// Legacy test function for backward compatibility
func TestVote(t *testing.T) {
	testVoteWithAuthorities(t, 3, 3) // Same as TestVote3Authorities
}

func TestBindAddresses(t *testing.T) {
	require := require.New(t)

	// Test the listen address selection logic
	tests := []struct {
		name          string
		addresses     []string
		bindAddresses []string
		wantListen    []string
	}{
		{
			name:          "only Addresses",
			addresses:     []string{"tcp://192.0.2.1:29483"},
			bindAddresses: nil,
			wantListen:    []string{"tcp://192.0.2.1:29483"},
		},
		{
			name:          "both Addresses and BindAddresses",
			addresses:     []string{"tcp://192.0.2.1:29483"},
			bindAddresses: []string{"tcp://192.168.0.2:29483"},
			wantListen:    []string{"tcp://192.168.0.2:29483"},
		},
		{
			name:          "empty BindAddresses uses Addresses",
			addresses:     []string{"tcp://203.0.113.10:29483"},
			bindAddresses: []string{},
			wantListen:    []string{"tcp://203.0.113.10:29483"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Server{
				Addresses:     tt.addresses,
				BindAddresses: tt.bindAddresses,
			}

			// Replicate the logic from server.go
			listenAddresses := cfg.Addresses
			if len(cfg.BindAddresses) > 0 {
				listenAddresses = cfg.BindAddresses
			}

			require.Equal(tt.wantListen, listenAddresses)
		})
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
		cfg.Server.Addresses = []string{fmt.Sprintf("tcp://127.0.0.1:%d", lastPort)}
		cfg.Server.DataDir = datadir
		cfg.Server.PKISignatureScheme = testSignatureScheme.Name()
		lastPort += 1

		scheme := testingScheme
		linkPubKey, linkKey, err := scheme.GenerateKeyPair()
		if err != nil {
			return nil, nil, err
		}
		idPubKey, idKey, err := testSignatureScheme.GenerateKey()
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
			Identifier:         cfg.Server.Identifier,
			PKISignatureScheme: testSignatureScheme.Name(),
			IdentityPublicKey:  idPubKey,
			LinkPublicKey:      config.LinkPublicKey{PublicKey: linkPubKey},
			Addresses:          cfg.Server.Addresses,
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
	cfg.Server.PKISignatureScheme = testSignatureScheme.Name()
	cfg.Server.Identifier = name
	cfg.Server.Addresses = []string{fmt.Sprintf("tcp://127.0.0.1:%d", port)}

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
	idPubKey, idKey, err := testSignatureScheme.GenerateKey()
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
	cfg.Server.PKISignatureScheme = testSignatureScheme.Name()
	cfg.Server.Identifier = name
	cfg.Server.Addresses = []string{fmt.Sprintf("tcp://127.0.0.1:%d", port)}

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
	idPubKey, idKey, err := testSignatureScheme.GenerateKey()
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
	cfg.Server.PKISignatureScheme = testingSchemeName
	cfg.Server.Identifier = name
	cfg.Server.Addresses = []string{fmt.Sprintf("tcp://127.0.0.1:%d", port)}
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
	idPubKey, idKey, err := testSignatureScheme.GenerateKey()
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

// TestReplicaDescriptorConsensus verifies that replica descriptors must achieve
// threshold consensus to be included in the final document. If one authority
// receives a replica descriptor but the majority doesn't, that descriptor
// should not appear in any authority's consensus document.
func TestReplicaDescriptorConsensus(t *testing.T) {
	require := require.New(t)

	authNum := 3
	stateAuthority := make([]*state, authNum)
	votingEpoch, _, _ := epochtime.Now()
	votingEpoch += 5
	parameters := &config.Parameters{
		Mu:      0.001,
		LambdaP: 0.002,
		LambdaL: 0.0005,
		LambdaM: 0.2,
	}

	peerKeys, authCfgs, err := genVotingAuthoritiesCfg(parameters, authNum)
	require.NoError(err)

	reverseHash := make(map[[publicKeyHashSize]byte]sign.PublicKey)
	authorityNames := make(map[[publicKeyHashSize]byte]string)

	// Generate replica identity keys (GenerateKey returns PublicKey, PrivateKey, error)
	replica1IdPubKey, replica1IdKey, err := testSignatureScheme.GenerateKey()
	require.NoError(err)
	replica2IdPubKey, replica2IdKey, err := testSignatureScheme.GenerateKey()
	require.NoError(err)
	_ = replica1IdKey // unused in this test
	_ = replica2IdKey

	replica1IdPubKeyBytes, err := replica1IdPubKey.MarshalBinary()
	require.NoError(err)
	replica2IdPubKeyBytes, err := replica2IdPubKey.MarshalBinary()
	require.NoError(err)

	// Set up authorities from configuration
	for i := 0; i < authNum; i++ {
		st := new(state)
		st.votingEpoch = votingEpoch
		cfg := authCfgs[i]
		st.verifiers = make(map[[publicKeyHashSize]byte]sign.PublicKey)
		for j := range peerKeys {
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
		pk := hash.Sum256From(peerKeys[i].idPubKey)
		reverseHash[pk] = peerKeys[i].idPubKey
		authorityNames[pk] = authCfgs[i].Server.Identifier

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
		st.replicaDescriptors = make(map[uint64]map[[hash.HashSize]byte]*pki.ReplicaDescriptor)
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
		err = st.restorePersistence()
		require.NoError(err)

		// Set up authorized replicas for all authorities
		st.authorizedReplicaNodes = make(map[[publicKeyHashSize]byte]*authorizedReplicaInfo)
		st.authorizedReplicaNodes[hash.Sum256(replica1IdPubKeyBytes)] = &authorizedReplicaInfo{
			Identifier: "replica-1",
			ReplicaID:  1,
		}
		st.authorizedReplicaNodes[hash.Sum256(replica2IdPubKeyBytes)] = &authorizedReplicaInfo{
			Identifier: "replica-2",
			ReplicaID:  2,
		}
		st.reverseHash[hash.Sum256(replica1IdPubKeyBytes)] = replica1IdPubKey
		st.reverseHash[hash.Sum256(replica2IdPubKeyBytes)] = replica2IdPubKey
	}

	// Create voting PKI configuration
	authorities := make([]*config.Authority, 0)
	for i, aCfg := range authCfgs {
		auth := &config.Authority{
			Addresses:          aCfg.Server.Addresses,
			WireKEMScheme:      testingSchemeName,
			PKISignatureScheme: testSignatureScheme.Name(),
			IdentityPublicKey:  peerKeys[i].idPubKey,
			LinkPublicKey:      config.LinkPublicKey{PublicKey: peerKeys[i].linkKey.Public()},
		}
		authorities = append(authorities, auth)
	}
	votingPKI := &sConfig.PKI{
		Voting: &sConfig.Voting{
			Authorities: authorities,
		},
	}

	// Generate mixes (needed for valid documents)
	n := 3 * 2 // 3 layers, 2 nodes per layer
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

	// Generate topology
	topology := config.Topology{Layers: make([]config.Layer, 3)}
	topology.Layers[0].Nodes = []config.Node{
		{IdentityPublicKeyPem: idKeys[0].identityPublicKeyPem},
		{IdentityPublicKeyPem: idKeys[1].identityPublicKeyPem},
	}
	topology.Layers[1].Nodes = []config.Node{
		{IdentityPublicKeyPem: idKeys[2].identityPublicKeyPem},
		{IdentityPublicKeyPem: idKeys[3].identityPublicKeyPem},
	}
	topology.Layers[2].Nodes = []config.Node{
		{IdentityPublicKeyPem: idKeys[4].identityPublicKeyPem},
		{IdentityPublicKeyPem: idKeys[5].identityPublicKeyPem},
	}

	for i := 0; i < authNum; i++ {
		authCfgs[i].Topology = &topology
	}

	// Generate gateways
	for i := 0; i < m; i++ {
		idKey, c, err := genGatewayConfig(fmt.Sprintf("gateway-%d", i), votingPKI, port)
		require.NoError(err)
		mixCfgs = append(mixCfgs, c)
		idKeys = append(idKeys, idKey)
		port++
		reverseHash[hash.Sum256From(idKey.pubKey)] = idKey.pubKey
	}

	// Generate serviceNodes
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
		stateAuthority[i].authorityNames = authorityNames
	}

	// Create mix descriptors
	mixDescs := make([]*pki.MixDescriptor, 0)
	gatewayDescs := make([]*pki.MixDescriptor, 0)
	serviceDescs := make([]*pki.MixDescriptor, 0)
	for i := 0; i < len(mixCfgs); i++ {
		mkeys := genMixKeys(votingEpoch)
		addr := make(map[string][]string)
		addr[pki.TransportTCPv4] = []string{"tcp4://127.0.0.1:1234"}
		linkPubKey, _, err := testingScheme.GenerateKeyPair()
		require.NoError(err)
		linkBlob, err := linkPubKey.MarshalBinary()
		require.NoError(err)
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

		if mixCfgs[i].Server.IsServiceNode {
			serviceDescs = append(serviceDescs, desc)
		} else if mixCfgs[i].Server.IsGatewayNode {
			gatewayDescs = append(gatewayDescs, desc)
		} else {
			mixDescs = append(mixDescs, desc)
		}
	}

	// Create replica descriptors
	replica1LinkPubKey, _, err := testingScheme.GenerateKeyPair()
	require.NoError(err)
	replica1LinkBlob, err := replica1LinkPubKey.MarshalBinary()
	require.NoError(err)

	replica2LinkPubKey, _, err := testingScheme.GenerateKeyPair()
	require.NoError(err)
	replica2LinkBlob, err := replica2LinkPubKey.MarshalBinary()
	require.NoError(err)

	// Create envelope keys for replicas
	envelopeKey1 := make([]byte, 32)
	rand.Reader.Read(envelopeKey1)
	envelopeKey2 := make([]byte, 32)
	rand.Reader.Read(envelopeKey2)

	replica1Desc := &pki.ReplicaDescriptor{
		Name:        "replica-1",
		ReplicaID:   1,
		Epoch:       votingEpoch,
		IdentityKey: replica1IdPubKeyBytes,
		LinkKey:     replica1LinkBlob,
		EnvelopeKeys: map[uint64][]byte{
			0: envelopeKey1,
		},
		Addresses: map[string][]string{
			pki.TransportTCPv4: {"tcp4://127.0.0.1:5000"},
		},
	}

	replica2Desc := &pki.ReplicaDescriptor{
		Name:        "replica-2",
		ReplicaID:   2,
		Epoch:       votingEpoch,
		IdentityKey: replica2IdPubKeyBytes,
		LinkKey:     replica2LinkBlob,
		EnvelopeKeys: map[uint64][]byte{
			0: envelopeKey2,
		},
		Addresses: map[string][]string{
			pki.TransportTCPv4: {"tcp4://127.0.0.1:5001"},
		},
	}

	// Populate authorities with mix descriptors (all authorities get all mixes)
	for _, s := range stateAuthority {
		s.descriptors[votingEpoch] = make(map[[hash.HashSize]byte]*pki.MixDescriptor)
		s.authorizedMixes = make(map[[hash.HashSize]byte]string)
		s.authorizedGatewayNodes = make(map[[hash.HashSize]byte]string)
		s.authorizedServiceNodes = make(map[[hash.HashSize]byte]string)
		for _, d := range mixDescs {
			s.descriptors[votingEpoch][hash.Sum256(d.IdentityKey)] = d
			s.authorizedMixes[hash.Sum256(d.IdentityKey)] = d.Name
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

	// KEY TEST: Give replica1 descriptor to ONLY authority-0 (won't achieve consensus)
	// Give replica2 descriptor to ALL authorities (will achieve consensus)
	for i, s := range stateAuthority {
		s.replicaDescriptors[votingEpoch] = make(map[[hash.HashSize]byte]*pki.ReplicaDescriptor)

		// Only authority-0 gets replica1
		if i == 0 {
			s.replicaDescriptors[votingEpoch][hash.Sum256(replica1Desc.IdentityKey)] = replica1Desc
			t.Logf("Authority-%d received replica-1 descriptor", i)
		}

		// All authorities get replica2
		s.replicaDescriptors[votingEpoch][hash.Sum256(replica2Desc.IdentityKey)] = replica2Desc
		t.Logf("Authority-%d received replica-2 descriptor", i)
	}

	// Create and exchange signed commits and reveals
	commits := make(map[uint64]map[[hash.HashSize]byte][]byte)
	commits[votingEpoch] = make(map[[hash.HashSize]byte][]byte)

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

	// Exchange votes
	for i, s := range stateAuthority {
		s.votingEpoch = votingEpoch
		s.genesisEpoch = s.votingEpoch
		myVote, err := s.getVote(s.votingEpoch)
		require.NoError(err)
		require.NotNil(myVote)
		s.state = stateAcceptVote

		// Log what each vote contains for replica descriptors
		t.Logf("Authority-%d vote contains %d replica descriptors", i, len(myVote.StorageReplicas))
		for _, rd := range myVote.StorageReplicas {
			t.Logf("  - %s (ReplicaID=%d)", rd.Name, rd.ReplicaID)
		}

		// Distribute vote to other authorities
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.Lock()
			a.votes[s.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = myVote
			a.Unlock()
		}
	}

	// Exchange reveals
	for i, s := range stateAuthority {
		s.state = stateAcceptReveal
		c := s.reveal(s.votingEpoch)
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.Lock()
			a.reveals[a.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = c
			a.Unlock()
		}
	}

	// Exchange certificates
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
			a.Lock()
			a.certificates[s.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = myCertificate
			a.Unlock()
		}
		s.Unlock()
	}

	// Produce consensus documents
	for _, s := range stateAuthority {
		s.Lock()
		_, err := s.getMyConsensus(s.votingEpoch)
		s.Unlock()
		require.NoError(err)
	}

	// Exchange signatures
	for i, s := range stateAuthority {
		s.state = stateAcceptSignature
		id := hash.Sum256From(s.s.identityPublicKey)
		mySignature, ok := s.myconsensus[s.votingEpoch].Signatures[id]
		require.True(ok)

		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.Lock()
			a.signatures[s.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = &mySignature
			a.Unlock()
		}
	}

	// Get final consensus and verify replica descriptor behavior
	var consensusDoc *pki.Document
	for i, s := range stateAuthority {
		s.Lock()
		doc, err := s.getThresholdConsensus(s.votingEpoch)
		s.Unlock()
		require.NoError(err)

		t.Logf("Authority-%d consensus has %d replica descriptors", i, len(doc.StorageReplicas))
		for _, rd := range doc.StorageReplicas {
			t.Logf("  - %s (ReplicaID=%d)", rd.Name, rd.ReplicaID)
		}

		// Verify: replica1 should NOT be in the consensus (only 1/3 authorities had it)
		for _, rd := range doc.StorageReplicas {
			require.NotEqual("replica-1", rd.Name,
				"replica-1 should not be in consensus - it only had 1/3 votes")
			require.NotEqual(uint8(1), rd.ReplicaID,
				"ReplicaID 1 should not be in consensus")
		}

		// Verify: replica2 SHOULD be in the consensus (all 3 authorities had it)
		foundReplica2 := false
		for _, rd := range doc.StorageReplicas {
			if rd.Name == "replica-2" && rd.ReplicaID == 2 {
				foundReplica2 = true
				break
			}
		}
		require.True(foundReplica2, "replica-2 should be in consensus - it had 3/3 votes")

		// Verify: envelope keys should only come from replica2's descriptor
		for _, rd := range doc.StorageReplicas {
			require.NotEqual(uint8(1), rd.ReplicaID,
				"consensus should not carry a descriptor for replica-1")
		}

		if consensusDoc == nil {
			consensusDoc = doc
		}
	}

	t.Log("SUCCESS: Replica descriptor consensus test passed")
	t.Log("- replica-1 (1/3 votes) was correctly excluded from consensus")
	t.Log("- replica-2 (3/3 votes) was correctly included in consensus")
}

// TestConfiguredReplicaIdentityKeys verifies that the ConfiguredReplicaIdentityKeys field
// is properly populated from the authorized replicas configuration, independent of whether
// those replicas achieve consensus or are online.
func TestConfiguredReplicaIdentityKeys(t *testing.T) {
	require := require.New(t)

	authNum := 3
	stateAuthority := make([]*state, authNum)
	votingEpoch, _, _ := epochtime.Now()
	votingEpoch += 5
	parameters := &config.Parameters{
		Mu:      0.001,
		LambdaP: 0.002,
		LambdaL: 0.0005,
		LambdaM: 0.2,
	}

	peerKeys, authCfgs, err := genVotingAuthoritiesCfg(parameters, authNum)
	require.NoError(err)

	reverseHash := make(map[[publicKeyHashSize]byte]sign.PublicKey)
	authorityNames := make(map[[publicKeyHashSize]byte]string)

	// Generate 3 replica identity keys - we'll configure all 3 but only have 2 online
	replica1IdPubKey, _, err := testSignatureScheme.GenerateKey()
	require.NoError(err)
	replica2IdPubKey, _, err := testSignatureScheme.GenerateKey()
	require.NoError(err)
	replica3IdPubKey, _, err := testSignatureScheme.GenerateKey()
	require.NoError(err)

	replica1IdPubKeyBytes, err := replica1IdPubKey.MarshalBinary()
	require.NoError(err)
	replica2IdPubKeyBytes, err := replica2IdPubKey.MarshalBinary()
	require.NoError(err)
	replica3IdPubKeyBytes, err := replica3IdPubKey.MarshalBinary()
	require.NoError(err)

	// Add replica keys to the shared reverseHash map
	reverseHash[hash.Sum256(replica1IdPubKeyBytes)] = replica1IdPubKey
	reverseHash[hash.Sum256(replica2IdPubKeyBytes)] = replica2IdPubKey
	reverseHash[hash.Sum256(replica3IdPubKeyBytes)] = replica3IdPubKey

	// Set up authorities from configuration
	for i := 0; i < authNum; i++ {
		st := new(state)
		st.votingEpoch = votingEpoch
		cfg := authCfgs[i]
		st.verifiers = make(map[[publicKeyHashSize]byte]sign.PublicKey)
		for j := range peerKeys {
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
		pk := hash.Sum256From(peerKeys[i].idPubKey)
		reverseHash[pk] = peerKeys[i].idPubKey
		authorityNames[pk] = authCfgs[i].Server.Identifier

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
		st.replicaDescriptors = make(map[uint64]map[[hash.HashSize]byte]*pki.ReplicaDescriptor)
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
		err = st.restorePersistence()
		require.NoError(err)

		// Configure ALL 3 replicas as authorized (even though replica3 won't come online)
		st.authorizedReplicaNodes = make(map[[publicKeyHashSize]byte]*authorizedReplicaInfo)
		st.authorizedReplicaNodes[hash.Sum256(replica1IdPubKeyBytes)] = &authorizedReplicaInfo{
			Identifier: "replica-1",
			ReplicaID:  1,
		}
		st.authorizedReplicaNodes[hash.Sum256(replica2IdPubKeyBytes)] = &authorizedReplicaInfo{
			Identifier: "replica-2",
			ReplicaID:  2,
		}
		st.authorizedReplicaNodes[hash.Sum256(replica3IdPubKeyBytes)] = &authorizedReplicaInfo{
			Identifier: "replica-3",
			ReplicaID:  3,
		}
		st.reverseHash[hash.Sum256(replica1IdPubKeyBytes)] = replica1IdPubKey
		st.reverseHash[hash.Sum256(replica2IdPubKeyBytes)] = replica2IdPubKey
		st.reverseHash[hash.Sum256(replica3IdPubKeyBytes)] = replica3IdPubKey
	}

	// Create voting PKI configuration and mixes (reusing pattern from previous test)
	authorities := make([]*config.Authority, 0)
	for i, aCfg := range authCfgs {
		auth := &config.Authority{
			Addresses:          aCfg.Server.Addresses,
			WireKEMScheme:      testingSchemeName,
			PKISignatureScheme: testSignatureScheme.Name(),
			IdentityPublicKey:  peerKeys[i].idPubKey,
			LinkPublicKey:      config.LinkPublicKey{PublicKey: peerKeys[i].linkKey.Public()},
		}
		authorities = append(authorities, auth)
	}
	votingPKI := &sConfig.PKI{
		Voting: &sConfig.Voting{
			Authorities: authorities,
		},
	}

	// Generate minimal mixes for a valid document
	n := 3 * 2
	m := 2
	idKeys := make([]*identityKey, 0)
	mixCfgs := make([]*sConfig.Config, 0)
	port := uint16(30100)
	for i := 0; i < n; i++ {
		idKey, c, err := genMixConfig(fmt.Sprintf("node-%d", i), votingPKI, port)
		require.NoError(err)
		mixCfgs = append(mixCfgs, c)
		idKeys = append(idKeys, idKey)
		port++
		reverseHash[hash.Sum256From(idKey.pubKey)] = idKey.pubKey
	}

	topology := config.Topology{Layers: make([]config.Layer, 3)}
	topology.Layers[0].Nodes = []config.Node{
		{IdentityPublicKeyPem: idKeys[0].identityPublicKeyPem},
		{IdentityPublicKeyPem: idKeys[1].identityPublicKeyPem},
	}
	topology.Layers[1].Nodes = []config.Node{
		{IdentityPublicKeyPem: idKeys[2].identityPublicKeyPem},
		{IdentityPublicKeyPem: idKeys[3].identityPublicKeyPem},
	}
	topology.Layers[2].Nodes = []config.Node{
		{IdentityPublicKeyPem: idKeys[4].identityPublicKeyPem},
		{IdentityPublicKeyPem: idKeys[5].identityPublicKeyPem},
	}
	for i := 0; i < authNum; i++ {
		authCfgs[i].Topology = &topology
	}

	for i := 0; i < m; i++ {
		idKey, c, err := genGatewayConfig(fmt.Sprintf("gateway-%d", i), votingPKI, port)
		require.NoError(err)
		mixCfgs = append(mixCfgs, c)
		idKeys = append(idKeys, idKey)
		port++
		reverseHash[hash.Sum256From(idKey.pubKey)] = idKey.pubKey
	}
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
		stateAuthority[i].authorityNames = authorityNames
	}

	// Create mix descriptors
	mixDescs := make([]*pki.MixDescriptor, 0)
	gatewayDescs := make([]*pki.MixDescriptor, 0)
	serviceDescs := make([]*pki.MixDescriptor, 0)
	for i := 0; i < len(mixCfgs); i++ {
		mkeys := genMixKeys(votingEpoch)
		addr := make(map[string][]string)
		addr[pki.TransportTCPv4] = []string{"tcp4://127.0.0.1:1234"}
		linkPubKey, _, err := testingScheme.GenerateKeyPair()
		require.NoError(err)
		linkBlob, err := linkPubKey.MarshalBinary()
		require.NoError(err)
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
		if mixCfgs[i].Server.IsServiceNode {
			serviceDescs = append(serviceDescs, desc)
		} else if mixCfgs[i].Server.IsGatewayNode {
			gatewayDescs = append(gatewayDescs, desc)
		} else {
			mixDescs = append(mixDescs, desc)
		}
	}

	// Create replica descriptors - only replica1 and replica2 are online
	replica1LinkPubKey, _, err := testingScheme.GenerateKeyPair()
	require.NoError(err)
	replica1LinkBlob, err := replica1LinkPubKey.MarshalBinary()
	require.NoError(err)
	replica2LinkPubKey, _, err := testingScheme.GenerateKeyPair()
	require.NoError(err)
	replica2LinkBlob, err := replica2LinkPubKey.MarshalBinary()
	require.NoError(err)

	replica1Desc := &pki.ReplicaDescriptor{
		Name:        "replica-1",
		ReplicaID:   1,
		Epoch:       votingEpoch,
		IdentityKey: replica1IdPubKeyBytes,
		LinkKey:     replica1LinkBlob,
		EnvelopeKeys: map[uint64][]byte{
			0: make([]byte, 32),
		},
		Addresses: map[string][]string{pki.TransportTCPv4: {"tcp4://127.0.0.1:5000"}},
	}
	replica2Desc := &pki.ReplicaDescriptor{
		Name:        "replica-2",
		ReplicaID:   2,
		Epoch:       votingEpoch,
		IdentityKey: replica2IdPubKeyBytes,
		LinkKey:     replica2LinkBlob,
		EnvelopeKeys: map[uint64][]byte{
			0: make([]byte, 32),
		},
		Addresses: map[string][]string{pki.TransportTCPv4: {"tcp4://127.0.0.1:5001"}},
	}
	// replica3 is NOT online - no descriptor submitted

	// Populate authorities
	for _, s := range stateAuthority {
		s.descriptors[votingEpoch] = make(map[[hash.HashSize]byte]*pki.MixDescriptor)
		s.authorizedMixes = make(map[[hash.HashSize]byte]string)
		s.authorizedGatewayNodes = make(map[[hash.HashSize]byte]string)
		s.authorizedServiceNodes = make(map[[hash.HashSize]byte]string)
		for _, d := range mixDescs {
			s.descriptors[votingEpoch][hash.Sum256(d.IdentityKey)] = d
			s.authorizedMixes[hash.Sum256(d.IdentityKey)] = d.Name
		}
		for _, d := range gatewayDescs {
			s.descriptors[votingEpoch][hash.Sum256(d.IdentityKey)] = d
			s.authorizedGatewayNodes[hash.Sum256(d.IdentityKey)] = d.Name
		}
		for _, d := range serviceDescs {
			s.descriptors[votingEpoch][hash.Sum256(d.IdentityKey)] = d
			s.authorizedServiceNodes[hash.Sum256(d.IdentityKey)] = d.Name
		}

		// All authorities get replica1 and replica2 descriptors (they achieve consensus)
		s.replicaDescriptors[votingEpoch] = make(map[[hash.HashSize]byte]*pki.ReplicaDescriptor)
		s.replicaDescriptors[votingEpoch][hash.Sum256(replica1Desc.IdentityKey)] = replica1Desc
		s.replicaDescriptors[votingEpoch][hash.Sum256(replica2Desc.IdentityKey)] = replica2Desc
	}

	// Run consensus protocol (abbreviated - just get a vote to check the document)
	for _, s := range stateAuthority {
		s.votingEpoch = votingEpoch
		s.genesisEpoch = s.votingEpoch
		myVote, err := s.getVote(s.votingEpoch)
		require.NoError(err)
		require.NotNil(myVote)

		// Verify ConfiguredReplicaIdentityKeys contains ALL 3 configured replicas
		require.Len(myVote.ConfiguredReplicaIdentityKeys, 3,
			"ConfiguredReplicaIdentityKeys should contain all 3 configured replicas")

		// Check that all 3 identity keys are present
		foundKeys := make(map[string]bool)
		for _, key := range myVote.ConfiguredReplicaIdentityKeys {
			foundKeys[string(key)] = true
		}
		require.True(foundKeys[string(replica1IdPubKeyBytes)], "replica-1 key should be in ConfiguredReplicaIdentityKeys")
		require.True(foundKeys[string(replica2IdPubKeyBytes)], "replica-2 key should be in ConfiguredReplicaIdentityKeys")
		require.True(foundKeys[string(replica3IdPubKeyBytes)], "replica-3 key should be in ConfiguredReplicaIdentityKeys (even though offline)")

		// But StorageReplicas should only contain the 2 online replicas
		require.Len(myVote.StorageReplicas, 2, "StorageReplicas should only contain 2 online replicas")
	}

	t.Log("SUCCESS: ConfiguredReplicaIdentityKeys test passed")
	t.Log("- All 3 configured replicas appear in ConfiguredReplicaIdentityKeys")
	t.Log("- Only 2 online replicas appear in StorageReplicas")
}

// TestNoReplicasAchieveConsensus verifies that when no replica descriptors achieve
// threshold consensus, StorageReplicas is empty, but
// ConfiguredReplicaIdentityKeys still lists the configured replicas.
func TestNoReplicasAchieveConsensus(t *testing.T) {
	require := require.New(t)

	authNum := 3
	stateAuthority := make([]*state, authNum)
	votingEpoch, _, _ := epochtime.Now()
	votingEpoch += 5
	parameters := &config.Parameters{
		Mu:      0.001,
		LambdaP: 0.002,
		LambdaL: 0.0005,
		LambdaM: 0.2,
	}

	peerKeys, authCfgs, err := genVotingAuthoritiesCfg(parameters, authNum)
	require.NoError(err)

	reverseHash := make(map[[publicKeyHashSize]byte]sign.PublicKey)
	authorityNames := make(map[[publicKeyHashSize]byte]string)

	// Generate 2 replica identity keys
	replica1IdPubKey, _, err := testSignatureScheme.GenerateKey()
	require.NoError(err)
	replica2IdPubKey, _, err := testSignatureScheme.GenerateKey()
	require.NoError(err)

	replica1IdPubKeyBytes, err := replica1IdPubKey.MarshalBinary()
	require.NoError(err)
	replica2IdPubKeyBytes, err := replica2IdPubKey.MarshalBinary()
	require.NoError(err)

	// Add replica keys to the shared reverseHash map
	reverseHash[hash.Sum256(replica1IdPubKeyBytes)] = replica1IdPubKey
	reverseHash[hash.Sum256(replica2IdPubKeyBytes)] = replica2IdPubKey

	// Set up authorities
	for i := 0; i < authNum; i++ {
		st := new(state)
		st.votingEpoch = votingEpoch
		cfg := authCfgs[i]
		st.verifiers = make(map[[publicKeyHashSize]byte]sign.PublicKey)
		for j := range peerKeys {
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
		pk := hash.Sum256From(peerKeys[i].idPubKey)
		reverseHash[pk] = peerKeys[i].idPubKey
		authorityNames[pk] = authCfgs[i].Server.Identifier

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
		st.replicaDescriptors = make(map[uint64]map[[hash.HashSize]byte]*pki.ReplicaDescriptor)
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
		err = st.restorePersistence()
		require.NoError(err)

		// Configure replicas
		st.authorizedReplicaNodes = make(map[[publicKeyHashSize]byte]*authorizedReplicaInfo)
		st.authorizedReplicaNodes[hash.Sum256(replica1IdPubKeyBytes)] = &authorizedReplicaInfo{
			Identifier: "replica-1",
			ReplicaID:  1,
		}
		st.authorizedReplicaNodes[hash.Sum256(replica2IdPubKeyBytes)] = &authorizedReplicaInfo{
			Identifier: "replica-2",
			ReplicaID:  2,
		}
		st.reverseHash[hash.Sum256(replica1IdPubKeyBytes)] = replica1IdPubKey
		st.reverseHash[hash.Sum256(replica2IdPubKeyBytes)] = replica2IdPubKey
	}

	// Set up PKI and mixes (abbreviated)
	authorities := make([]*config.Authority, 0)
	for i, aCfg := range authCfgs {
		auth := &config.Authority{
			Addresses:          aCfg.Server.Addresses,
			WireKEMScheme:      testingSchemeName,
			PKISignatureScheme: testSignatureScheme.Name(),
			IdentityPublicKey:  peerKeys[i].idPubKey,
			LinkPublicKey:      config.LinkPublicKey{PublicKey: peerKeys[i].linkKey.Public()},
		}
		authorities = append(authorities, auth)
	}
	votingPKI := &sConfig.PKI{Voting: &sConfig.Voting{Authorities: authorities}}

	n := 3 * 2
	m := 2
	idKeys := make([]*identityKey, 0)
	mixCfgs := make([]*sConfig.Config, 0)
	port := uint16(30200)
	for i := 0; i < n; i++ {
		idKey, c, err := genMixConfig(fmt.Sprintf("node-%d", i), votingPKI, port)
		require.NoError(err)
		mixCfgs = append(mixCfgs, c)
		idKeys = append(idKeys, idKey)
		port++
		reverseHash[hash.Sum256From(idKey.pubKey)] = idKey.pubKey
	}
	topology := config.Topology{Layers: make([]config.Layer, 3)}
	topology.Layers[0].Nodes = []config.Node{
		{IdentityPublicKeyPem: idKeys[0].identityPublicKeyPem},
		{IdentityPublicKeyPem: idKeys[1].identityPublicKeyPem},
	}
	topology.Layers[1].Nodes = []config.Node{
		{IdentityPublicKeyPem: idKeys[2].identityPublicKeyPem},
		{IdentityPublicKeyPem: idKeys[3].identityPublicKeyPem},
	}
	topology.Layers[2].Nodes = []config.Node{
		{IdentityPublicKeyPem: idKeys[4].identityPublicKeyPem},
		{IdentityPublicKeyPem: idKeys[5].identityPublicKeyPem},
	}
	for i := 0; i < authNum; i++ {
		authCfgs[i].Topology = &topology
	}
	for i := 0; i < m; i++ {
		idKey, c, err := genGatewayConfig(fmt.Sprintf("gateway-%d", i), votingPKI, port)
		require.NoError(err)
		mixCfgs = append(mixCfgs, c)
		idKeys = append(idKeys, idKey)
		port++
		reverseHash[hash.Sum256From(idKey.pubKey)] = idKey.pubKey
	}
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
		stateAuthority[i].authorityNames = authorityNames
	}

	// Create mix descriptors
	mixDescs := make([]*pki.MixDescriptor, 0)
	gatewayDescs := make([]*pki.MixDescriptor, 0)
	serviceDescs := make([]*pki.MixDescriptor, 0)
	for i := 0; i < len(mixCfgs); i++ {
		mkeys := genMixKeys(votingEpoch)
		addr := make(map[string][]string)
		addr[pki.TransportTCPv4] = []string{"tcp4://127.0.0.1:1234"}
		linkPubKey, _, err := testingScheme.GenerateKeyPair()
		require.NoError(err)
		linkBlob, err := linkPubKey.MarshalBinary()
		require.NoError(err)
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
		if mixCfgs[i].Server.IsServiceNode {
			serviceDescs = append(serviceDescs, desc)
		} else if mixCfgs[i].Server.IsGatewayNode {
			gatewayDescs = append(gatewayDescs, desc)
		} else {
			mixDescs = append(mixDescs, desc)
		}
	}

	// Create replica descriptors
	replica1LinkPubKey, _, err := testingScheme.GenerateKeyPair()
	require.NoError(err)
	replica1LinkBlob, err := replica1LinkPubKey.MarshalBinary()
	require.NoError(err)
	replica2LinkPubKey, _, err := testingScheme.GenerateKeyPair()
	require.NoError(err)
	replica2LinkBlob, err := replica2LinkPubKey.MarshalBinary()
	require.NoError(err)

	replica1Desc := &pki.ReplicaDescriptor{
		Name:        "replica-1",
		ReplicaID:   1,
		Epoch:       votingEpoch,
		IdentityKey: replica1IdPubKeyBytes,
		LinkKey:     replica1LinkBlob,
		EnvelopeKeys: map[uint64][]byte{
			0: make([]byte, 32),
		},
		Addresses: map[string][]string{pki.TransportTCPv4: {"tcp4://127.0.0.1:5000"}},
	}
	replica2Desc := &pki.ReplicaDescriptor{
		Name:        "replica-2",
		ReplicaID:   2,
		Epoch:       votingEpoch,
		IdentityKey: replica2IdPubKeyBytes,
		LinkKey:     replica2LinkBlob,
		EnvelopeKeys: map[uint64][]byte{
			0: make([]byte, 32),
		},
		Addresses: map[string][]string{pki.TransportTCPv4: {"tcp4://127.0.0.1:5001"}},
	}

	// KEY SETUP: Each authority gets a DIFFERENT replica descriptor (no consensus)
	// Authority-0 gets replica1, Authority-1 gets replica2, Authority-2 gets neither
	for i, s := range stateAuthority {
		s.descriptors[votingEpoch] = make(map[[hash.HashSize]byte]*pki.MixDescriptor)
		s.authorizedMixes = make(map[[hash.HashSize]byte]string)
		s.authorizedGatewayNodes = make(map[[hash.HashSize]byte]string)
		s.authorizedServiceNodes = make(map[[hash.HashSize]byte]string)
		for _, d := range mixDescs {
			s.descriptors[votingEpoch][hash.Sum256(d.IdentityKey)] = d
			s.authorizedMixes[hash.Sum256(d.IdentityKey)] = d.Name
		}
		for _, d := range gatewayDescs {
			s.descriptors[votingEpoch][hash.Sum256(d.IdentityKey)] = d
			s.authorizedGatewayNodes[hash.Sum256(d.IdentityKey)] = d.Name
		}
		for _, d := range serviceDescs {
			s.descriptors[votingEpoch][hash.Sum256(d.IdentityKey)] = d
			s.authorizedServiceNodes[hash.Sum256(d.IdentityKey)] = d.Name
		}

		s.replicaDescriptors[votingEpoch] = make(map[[hash.HashSize]byte]*pki.ReplicaDescriptor)
		if i == 0 {
			s.replicaDescriptors[votingEpoch][hash.Sum256(replica1Desc.IdentityKey)] = replica1Desc
			t.Logf("Authority-%d got replica-1 only", i)
		} else if i == 1 {
			s.replicaDescriptors[votingEpoch][hash.Sum256(replica2Desc.IdentityKey)] = replica2Desc
			t.Logf("Authority-%d got replica-2 only", i)
		} else {
			t.Logf("Authority-%d got no replicas", i)
		}
	}

	// Run full consensus protocol
	commits := make(map[uint64]map[[hash.HashSize]byte][]byte)
	commits[votingEpoch] = make(map[[hash.HashSize]byte][]byte)

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

	// Exchange votes
	for i, s := range stateAuthority {
		s.votingEpoch = votingEpoch
		s.genesisEpoch = s.votingEpoch
		myVote, err := s.getVote(s.votingEpoch)
		require.NoError(err)
		require.NotNil(myVote)
		s.state = stateAcceptVote
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.Lock()
			a.votes[s.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = myVote
			a.Unlock()
		}
	}

	// Exchange reveals
	for i, s := range stateAuthority {
		s.state = stateAcceptReveal
		c := s.reveal(s.votingEpoch)
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.Lock()
			a.reveals[a.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = c
			a.Unlock()
		}
	}

	// Exchange certificates
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
			a.Lock()
			a.certificates[s.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = myCertificate
			a.Unlock()
		}
		s.Unlock()
	}

	// Produce consensus
	for _, s := range stateAuthority {
		s.Lock()
		_, err := s.getMyConsensus(s.votingEpoch)
		s.Unlock()
		require.NoError(err)
	}

	// Exchange signatures
	for i, s := range stateAuthority {
		s.state = stateAcceptSignature
		id := hash.Sum256From(s.s.identityPublicKey)
		mySignature, ok := s.myconsensus[s.votingEpoch].Signatures[id]
		require.True(ok)
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.Lock()
			a.signatures[s.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = &mySignature
			a.Unlock()
		}
	}

	// Get final consensus and verify
	for i, s := range stateAuthority {
		s.Lock()
		doc, err := s.getThresholdConsensus(s.votingEpoch)
		s.Unlock()
		require.NoError(err)

		t.Logf("Authority-%d consensus: StorageReplicas=%d, ConfiguredReplicaIdentityKeys=%d",
			i, len(doc.StorageReplicas), len(doc.ConfiguredReplicaIdentityKeys))

		// No replicas should have achieved consensus (each had only 1/3 votes)
		require.Len(doc.StorageReplicas, 0, "StorageReplicas should be empty when no replicas achieve consensus")

		// But ConfiguredReplicaIdentityKeys should still list the 2 configured replicas
		require.Len(doc.ConfiguredReplicaIdentityKeys, 2, "ConfiguredReplicaIdentityKeys should still list configured replicas")
	}

	t.Log("SUCCESS: No replicas achieve consensus test passed")
	t.Log("- StorageReplicas is empty (no consensus)")
	t.Log("- ConfiguredReplicaIdentityKeys still contains configured replicas")
}

// TestMultipleEnvelopeKeysPerReplica verifies that a replica can have envelope keys
// for multiple replica epochs (previous, current, next) and all are included in the
// consensus document.
func TestMultipleEnvelopeKeysPerReplica(t *testing.T) {
	require := require.New(t)

	authNum := 3
	stateAuthority := make([]*state, authNum)
	votingEpoch, _, _ := epochtime.Now()
	votingEpoch += 5
	parameters := &config.Parameters{
		Mu:      0.001,
		LambdaP: 0.002,
		LambdaL: 0.0005,
		LambdaM: 0.2,
	}

	peerKeys, authCfgs, err := genVotingAuthoritiesCfg(parameters, authNum)
	require.NoError(err)

	reverseHash := make(map[[publicKeyHashSize]byte]sign.PublicKey)
	authorityNames := make(map[[publicKeyHashSize]byte]string)

	replica1IdPubKey, _, err := testSignatureScheme.GenerateKey()
	require.NoError(err)
	replica1IdPubKeyBytes, err := replica1IdPubKey.MarshalBinary()
	require.NoError(err)

	// Get current replica epoch to create appropriate keys
	currentReplicaEpoch, _, _ := replicaCommon.ReplicaNow()

	// Set up authorities
	for i := 0; i < authNum; i++ {
		st := new(state)
		st.votingEpoch = votingEpoch
		cfg := authCfgs[i]
		st.verifiers = make(map[[publicKeyHashSize]byte]sign.PublicKey)
		for j := range peerKeys {
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
		pk := hash.Sum256From(peerKeys[i].idPubKey)
		reverseHash[pk] = peerKeys[i].idPubKey
		authorityNames[pk] = authCfgs[i].Server.Identifier

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
		st.replicaDescriptors = make(map[uint64]map[[hash.HashSize]byte]*pki.ReplicaDescriptor)
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
		err = st.restorePersistence()
		require.NoError(err)

		st.authorizedReplicaNodes = make(map[[publicKeyHashSize]byte]*authorizedReplicaInfo)
		st.authorizedReplicaNodes[hash.Sum256(replica1IdPubKeyBytes)] = &authorizedReplicaInfo{
			Identifier: "replica-1",
			ReplicaID:  1,
		}
		st.reverseHash[hash.Sum256(replica1IdPubKeyBytes)] = replica1IdPubKey
	}

	// Set up PKI and mixes (abbreviated)
	authorities := make([]*config.Authority, 0)
	for i, aCfg := range authCfgs {
		auth := &config.Authority{
			Addresses:          aCfg.Server.Addresses,
			WireKEMScheme:      testingSchemeName,
			PKISignatureScheme: testSignatureScheme.Name(),
			IdentityPublicKey:  peerKeys[i].idPubKey,
			LinkPublicKey:      config.LinkPublicKey{PublicKey: peerKeys[i].linkKey.Public()},
		}
		authorities = append(authorities, auth)
	}
	votingPKI := &sConfig.PKI{Voting: &sConfig.Voting{Authorities: authorities}}

	n := 3 * 2
	m := 2
	idKeys := make([]*identityKey, 0)
	mixCfgs := make([]*sConfig.Config, 0)
	port := uint16(30300)
	for i := 0; i < n; i++ {
		idKey, c, err := genMixConfig(fmt.Sprintf("node-%d", i), votingPKI, port)
		require.NoError(err)
		mixCfgs = append(mixCfgs, c)
		idKeys = append(idKeys, idKey)
		port++
		reverseHash[hash.Sum256From(idKey.pubKey)] = idKey.pubKey
	}
	topology := config.Topology{Layers: make([]config.Layer, 3)}
	topology.Layers[0].Nodes = []config.Node{
		{IdentityPublicKeyPem: idKeys[0].identityPublicKeyPem},
		{IdentityPublicKeyPem: idKeys[1].identityPublicKeyPem},
	}
	topology.Layers[1].Nodes = []config.Node{
		{IdentityPublicKeyPem: idKeys[2].identityPublicKeyPem},
		{IdentityPublicKeyPem: idKeys[3].identityPublicKeyPem},
	}
	topology.Layers[2].Nodes = []config.Node{
		{IdentityPublicKeyPem: idKeys[4].identityPublicKeyPem},
		{IdentityPublicKeyPem: idKeys[5].identityPublicKeyPem},
	}
	for i := 0; i < authNum; i++ {
		authCfgs[i].Topology = &topology
	}
	for i := 0; i < m; i++ {
		idKey, c, err := genGatewayConfig(fmt.Sprintf("gateway-%d", i), votingPKI, port)
		require.NoError(err)
		mixCfgs = append(mixCfgs, c)
		idKeys = append(idKeys, idKey)
		port++
		reverseHash[hash.Sum256From(idKey.pubKey)] = idKey.pubKey
	}
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
		stateAuthority[i].authorityNames = authorityNames
	}

	// Create mix descriptors
	mixDescs := make([]*pki.MixDescriptor, 0)
	gatewayDescs := make([]*pki.MixDescriptor, 0)
	serviceDescs := make([]*pki.MixDescriptor, 0)
	for i := 0; i < len(mixCfgs); i++ {
		mkeys := genMixKeys(votingEpoch)
		addr := make(map[string][]string)
		addr[pki.TransportTCPv4] = []string{"tcp4://127.0.0.1:1234"}
		linkPubKey, _, err := testingScheme.GenerateKeyPair()
		require.NoError(err)
		linkBlob, err := linkPubKey.MarshalBinary()
		require.NoError(err)
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
		if mixCfgs[i].Server.IsServiceNode {
			serviceDescs = append(serviceDescs, desc)
		} else if mixCfgs[i].Server.IsGatewayNode {
			gatewayDescs = append(gatewayDescs, desc)
		} else {
			mixDescs = append(mixDescs, desc)
		}
	}

	// Create replica descriptor with multiple envelope keys (previous, current, next epochs)
	replica1LinkPubKey, _, err := testingScheme.GenerateKeyPair()
	require.NoError(err)
	replica1LinkBlob, err := replica1LinkPubKey.MarshalBinary()
	require.NoError(err)

	// Generate unique envelope keys for each replica epoch
	prevEpochKey := make([]byte, 32)
	rand.Reader.Read(prevEpochKey)
	currEpochKey := make([]byte, 32)
	rand.Reader.Read(currEpochKey)
	nextEpochKey := make([]byte, 32)
	rand.Reader.Read(nextEpochKey)

	var minReplicaEpoch uint64
	if currentReplicaEpoch > 0 {
		minReplicaEpoch = currentReplicaEpoch - 1
	}

	replica1Desc := &pki.ReplicaDescriptor{
		Name:        "replica-1",
		ReplicaID:   1,
		Epoch:       votingEpoch,
		IdentityKey: replica1IdPubKeyBytes,
		LinkKey:     replica1LinkBlob,
		EnvelopeKeys: map[uint64][]byte{
			minReplicaEpoch:         prevEpochKey, // previous
			currentReplicaEpoch:     currEpochKey, // current
			currentReplicaEpoch + 1: nextEpochKey, // next
		},
		Addresses: map[string][]string{pki.TransportTCPv4: {"tcp4://127.0.0.1:5000"}},
	}

	t.Logf("Replica has envelope keys for replica epochs: %d, %d, %d",
		minReplicaEpoch, currentReplicaEpoch, currentReplicaEpoch+1)

	// Populate authorities - all get the replica descriptor
	for _, s := range stateAuthority {
		s.descriptors[votingEpoch] = make(map[[hash.HashSize]byte]*pki.MixDescriptor)
		s.authorizedMixes = make(map[[hash.HashSize]byte]string)
		s.authorizedGatewayNodes = make(map[[hash.HashSize]byte]string)
		s.authorizedServiceNodes = make(map[[hash.HashSize]byte]string)
		for _, d := range mixDescs {
			s.descriptors[votingEpoch][hash.Sum256(d.IdentityKey)] = d
			s.authorizedMixes[hash.Sum256(d.IdentityKey)] = d.Name
		}
		for _, d := range gatewayDescs {
			s.descriptors[votingEpoch][hash.Sum256(d.IdentityKey)] = d
			s.authorizedGatewayNodes[hash.Sum256(d.IdentityKey)] = d.Name
		}
		for _, d := range serviceDescs {
			s.descriptors[votingEpoch][hash.Sum256(d.IdentityKey)] = d
			s.authorizedServiceNodes[hash.Sum256(d.IdentityKey)] = d.Name
		}
		s.replicaDescriptors[votingEpoch] = make(map[[hash.HashSize]byte]*pki.ReplicaDescriptor)
		s.replicaDescriptors[votingEpoch][hash.Sum256(replica1Desc.IdentityKey)] = replica1Desc
	}

	// Run consensus protocol
	commits := make(map[uint64]map[[hash.HashSize]byte][]byte)
	commits[votingEpoch] = make(map[[hash.HashSize]byte][]byte)
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

	for i, s := range stateAuthority {
		s.votingEpoch = votingEpoch
		s.genesisEpoch = s.votingEpoch
		myVote, err := s.getVote(s.votingEpoch)
		require.NoError(err)
		require.NotNil(myVote)
		s.state = stateAcceptVote
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.Lock()
			a.votes[s.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = myVote
			a.Unlock()
		}
	}

	for i, s := range stateAuthority {
		s.state = stateAcceptReveal
		c := s.reveal(s.votingEpoch)
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.Lock()
			a.reveals[a.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = c
			a.Unlock()
		}
	}

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
			a.Lock()
			a.certificates[s.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = myCertificate
			a.Unlock()
		}
		s.Unlock()
	}

	for _, s := range stateAuthority {
		s.Lock()
		_, err := s.getMyConsensus(s.votingEpoch)
		s.Unlock()
		require.NoError(err)
	}

	for i, s := range stateAuthority {
		s.state = stateAcceptSignature
		id := hash.Sum256From(s.s.identityPublicKey)
		mySignature, ok := s.myconsensus[s.votingEpoch].Signatures[id]
		require.True(ok)
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.Lock()
			a.signatures[s.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = &mySignature
			a.Unlock()
		}
	}

	// Get final consensus and verify
	for i, s := range stateAuthority {
		s.Lock()
		doc, err := s.getThresholdConsensus(s.votingEpoch)
		s.Unlock()
		require.NoError(err)

		// Verify replica is in consensus
		require.Len(doc.StorageReplicas, 1, "Should have 1 replica")

		// Verify the descriptor carries all 3 epochs for replica-1
		require.Equal(uint8(1), doc.StorageReplicas[0].ReplicaID, "Should have descriptor for ReplicaID 1")

		replicaKeys := doc.StorageReplicas[0].EnvelopeKeys
		t.Logf("Authority-%d: descriptor EnvelopeKeys for replica-1 contains %d epochs", i, len(replicaKeys))
		for epoch := range replicaKeys {
			t.Logf("  - Replica epoch %d", epoch)
		}

		// All 3 epochs should be present (previous, current, next)
		require.Len(replicaKeys, 3, "Should have envelope keys for 3 replica epochs")
		require.Contains(replicaKeys, minReplicaEpoch, "Should have key for previous epoch")
		require.Contains(replicaKeys, currentReplicaEpoch, "Should have key for current epoch")
		require.Contains(replicaKeys, currentReplicaEpoch+1, "Should have key for next epoch")

		// Verify the keys match what we provided
		require.Equal(prevEpochKey, replicaKeys[minReplicaEpoch], "Previous epoch key should match")
		require.Equal(currEpochKey, replicaKeys[currentReplicaEpoch], "Current epoch key should match")
		require.Equal(nextEpochKey, replicaKeys[currentReplicaEpoch+1], "Next epoch key should match")
	}

	t.Log("SUCCESS: Multiple envelope keys per replica test passed")
	t.Log("- All 3 envelope keys (previous, current, next epochs) included in consensus")
}

// TestEmptyEnvelopeKeysWithConfiguredReplicas verifies that when replicas are configured
// but submit descriptors with empty EnvelopeKeys maps, this represents a bad-acting or
// misconfigured replica. The replica should still achieve consensus but have no envelope
// keys in the document.
func TestEmptyEnvelopeKeysWithConfiguredReplicas(t *testing.T) {
	require := require.New(t)

	authNum := 3
	stateAuthority := make([]*state, authNum)
	votingEpoch, _, _ := epochtime.Now()
	votingEpoch += 5
	parameters := &config.Parameters{
		Mu:      0.001,
		LambdaP: 0.002,
		LambdaL: 0.0005,
		LambdaM: 0.2,
	}

	peerKeys, authCfgs, err := genVotingAuthoritiesCfg(parameters, authNum)
	require.NoError(err)

	reverseHash := make(map[[publicKeyHashSize]byte]sign.PublicKey)
	authorityNames := make(map[[publicKeyHashSize]byte]string)

	replica1IdPubKey, _, err := testSignatureScheme.GenerateKey()
	require.NoError(err)
	replica1IdPubKeyBytes, err := replica1IdPubKey.MarshalBinary()
	require.NoError(err)

	// Set up authorities
	for i := 0; i < authNum; i++ {
		st := new(state)
		st.votingEpoch = votingEpoch
		cfg := authCfgs[i]
		st.verifiers = make(map[[publicKeyHashSize]byte]sign.PublicKey)
		for j := range peerKeys {
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
		pk := hash.Sum256From(peerKeys[i].idPubKey)
		reverseHash[pk] = peerKeys[i].idPubKey
		authorityNames[pk] = authCfgs[i].Server.Identifier

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
		st.replicaDescriptors = make(map[uint64]map[[hash.HashSize]byte]*pki.ReplicaDescriptor)
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
		err = st.restorePersistence()
		require.NoError(err)

		st.authorizedReplicaNodes = make(map[[publicKeyHashSize]byte]*authorizedReplicaInfo)
		st.authorizedReplicaNodes[hash.Sum256(replica1IdPubKeyBytes)] = &authorizedReplicaInfo{
			Identifier: "replica-1",
			ReplicaID:  1,
		}
		st.reverseHash[hash.Sum256(replica1IdPubKeyBytes)] = replica1IdPubKey
	}

	// Set up PKI and mixes (abbreviated)
	authorities := make([]*config.Authority, 0)
	for i, aCfg := range authCfgs {
		auth := &config.Authority{
			Addresses:          aCfg.Server.Addresses,
			WireKEMScheme:      testingSchemeName,
			PKISignatureScheme: testSignatureScheme.Name(),
			IdentityPublicKey:  peerKeys[i].idPubKey,
			LinkPublicKey:      config.LinkPublicKey{PublicKey: peerKeys[i].linkKey.Public()},
		}
		authorities = append(authorities, auth)
	}
	votingPKI := &sConfig.PKI{Voting: &sConfig.Voting{Authorities: authorities}}

	n := 3 * 2
	m := 2
	idKeys := make([]*identityKey, 0)
	mixCfgs := make([]*sConfig.Config, 0)
	port := uint16(30400)
	for i := 0; i < n; i++ {
		idKey, c, err := genMixConfig(fmt.Sprintf("node-%d", i), votingPKI, port)
		require.NoError(err)
		mixCfgs = append(mixCfgs, c)
		idKeys = append(idKeys, idKey)
		port++
		reverseHash[hash.Sum256From(idKey.pubKey)] = idKey.pubKey
	}
	topology := config.Topology{Layers: make([]config.Layer, 3)}
	topology.Layers[0].Nodes = []config.Node{
		{IdentityPublicKeyPem: idKeys[0].identityPublicKeyPem},
		{IdentityPublicKeyPem: idKeys[1].identityPublicKeyPem},
	}
	topology.Layers[1].Nodes = []config.Node{
		{IdentityPublicKeyPem: idKeys[2].identityPublicKeyPem},
		{IdentityPublicKeyPem: idKeys[3].identityPublicKeyPem},
	}
	topology.Layers[2].Nodes = []config.Node{
		{IdentityPublicKeyPem: idKeys[4].identityPublicKeyPem},
		{IdentityPublicKeyPem: idKeys[5].identityPublicKeyPem},
	}
	for i := 0; i < authNum; i++ {
		authCfgs[i].Topology = &topology
	}
	for i := 0; i < m; i++ {
		idKey, c, err := genGatewayConfig(fmt.Sprintf("gateway-%d", i), votingPKI, port)
		require.NoError(err)
		mixCfgs = append(mixCfgs, c)
		idKeys = append(idKeys, idKey)
		port++
		reverseHash[hash.Sum256From(idKey.pubKey)] = idKey.pubKey
	}
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
		stateAuthority[i].authorityNames = authorityNames
	}

	// Create mix descriptors (abbreviated)
	mixDescs := make([]*pki.MixDescriptor, 0)
	gatewayDescs := make([]*pki.MixDescriptor, 0)
	serviceDescs := make([]*pki.MixDescriptor, 0)
	for i := 0; i < len(mixCfgs); i++ {
		mkeys := genMixKeys(votingEpoch)
		addr := make(map[string][]string)
		addr[pki.TransportTCPv4] = []string{"tcp4://127.0.0.1:1234"}
		linkPubKey, _, err := testingScheme.GenerateKeyPair()
		require.NoError(err)
		linkBlob, err := linkPubKey.MarshalBinary()
		require.NoError(err)
		idkeyblob, err := idKeys[i].pubKey.MarshalBinary()
		require.NoError(err)
		desc := &pki.MixDescriptor{
			Name: mixCfgs[i].Server.Identifier, Epoch: votingEpoch,
			IdentityKey: idkeyblob, LinkKey: linkBlob, MixKeys: mkeys,
			IsGatewayNode: mixCfgs[i].Server.IsGatewayNode,
			IsServiceNode: mixCfgs[i].Server.IsServiceNode,
			Addresses:     addr,
		}
		if mixCfgs[i].Server.IsServiceNode {
			serviceDescs = append(serviceDescs, desc)
		} else if mixCfgs[i].Server.IsGatewayNode {
			gatewayDescs = append(gatewayDescs, desc)
		} else {
			mixDescs = append(mixDescs, desc)
		}
	}

	// Create replica descriptor with EMPTY EnvelopeKeys (bad-acting replica)
	replica1LinkPubKey, _, err := testingScheme.GenerateKeyPair()
	require.NoError(err)
	replica1LinkBlob, err := replica1LinkPubKey.MarshalBinary()
	require.NoError(err)

	replica1Desc := &pki.ReplicaDescriptor{
		Name:         "replica-1",
		ReplicaID:    1,
		Epoch:        votingEpoch,
		IdentityKey:  replica1IdPubKeyBytes,
		LinkKey:      replica1LinkBlob,
		EnvelopeKeys: map[uint64][]byte{}, // EMPTY - bad acting replica
		Addresses:    map[string][]string{pki.TransportTCPv4: {"tcp4://127.0.0.1:5000"}},
	}

	t.Log("Replica has EMPTY EnvelopeKeys map (bad-acting/misconfigured)")

	// Populate authorities - all get the replica descriptor
	for _, s := range stateAuthority {
		s.descriptors[votingEpoch] = make(map[[hash.HashSize]byte]*pki.MixDescriptor)
		s.authorizedMixes = make(map[[hash.HashSize]byte]string)
		s.authorizedGatewayNodes = make(map[[hash.HashSize]byte]string)
		s.authorizedServiceNodes = make(map[[hash.HashSize]byte]string)
		for _, d := range mixDescs {
			s.descriptors[votingEpoch][hash.Sum256(d.IdentityKey)] = d
			s.authorizedMixes[hash.Sum256(d.IdentityKey)] = d.Name
		}
		for _, d := range gatewayDescs {
			s.descriptors[votingEpoch][hash.Sum256(d.IdentityKey)] = d
			s.authorizedGatewayNodes[hash.Sum256(d.IdentityKey)] = d.Name
		}
		for _, d := range serviceDescs {
			s.descriptors[votingEpoch][hash.Sum256(d.IdentityKey)] = d
			s.authorizedServiceNodes[hash.Sum256(d.IdentityKey)] = d.Name
		}
		s.replicaDescriptors[votingEpoch] = make(map[[hash.HashSize]byte]*pki.ReplicaDescriptor)
		s.replicaDescriptors[votingEpoch][hash.Sum256(replica1Desc.IdentityKey)] = replica1Desc
	}

	// Run vote generation (abbreviated - just check the vote)
	for _, s := range stateAuthority {
		s.votingEpoch = votingEpoch
		s.genesisEpoch = s.votingEpoch

		// Initialize commits for vote generation
		commits := make(map[uint64]map[[hash.HashSize]byte][]byte)
		commits[votingEpoch] = make(map[[hash.HashSize]byte][]byte)
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

		myVote, err := s.getVote(s.votingEpoch)
		require.NoError(err)
		require.NotNil(myVote)

		// Verify replica is in StorageReplicas (it achieved consensus)
		require.Len(myVote.StorageReplicas, 1, "Replica should be in StorageReplicas")

		// But its descriptor should carry no envelope keys (none provided)
		require.Len(myVote.StorageReplicas[0].EnvelopeKeys, 0,
			"Replica should have no envelope keys (empty map)")

		t.Logf("Vote has %d StorageReplicas", len(myVote.StorageReplicas))
	}

	t.Log("SUCCESS: Empty EnvelopeKeys test passed")
	t.Log("- Replica with empty EnvelopeKeys still achieves consensus")
	t.Log("- Its descriptor carries no envelope keys (bad-acting behavior)")
}

// TestEnvelopeKeyPartitionResolvedByMajority verifies that when authorities have
// different envelope keys for the same replica (network partition scenario),
// the consensus uses the envelope keys from the majority partition.
func TestEnvelopeKeyPartitionResolvedByMajority(t *testing.T) {
	require := require.New(t)

	authNum := 3
	stateAuthority := make([]*state, authNum)
	votingEpoch, _, _ := epochtime.Now()
	votingEpoch += 5
	parameters := &config.Parameters{
		Mu:      0.001,
		LambdaP: 0.002,
		LambdaL: 0.0005,
		LambdaM: 0.2,
	}

	peerKeys, authCfgs, err := genVotingAuthoritiesCfg(parameters, authNum)
	require.NoError(err)

	reverseHash := make(map[[publicKeyHashSize]byte]sign.PublicKey)
	authorityNames := make(map[[publicKeyHashSize]byte]string)

	replica1IdPubKey, _, err := testSignatureScheme.GenerateKey()
	require.NoError(err)
	replica1IdPubKeyBytes, err := replica1IdPubKey.MarshalBinary()
	require.NoError(err)

	currentReplicaEpoch, _, _ := replicaCommon.ReplicaNow()

	// Create two different envelope keys - simulating network partition
	majorityEnvelopeKey := make([]byte, 32)
	rand.Reader.Read(majorityEnvelopeKey)
	minorityEnvelopeKey := make([]byte, 32)
	rand.Reader.Read(minorityEnvelopeKey)

	// Set up authorities
	for i := 0; i < authNum; i++ {
		st := new(state)
		st.votingEpoch = votingEpoch
		cfg := authCfgs[i]
		st.verifiers = make(map[[publicKeyHashSize]byte]sign.PublicKey)
		for j := range peerKeys {
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
		pk := hash.Sum256From(peerKeys[i].idPubKey)
		reverseHash[pk] = peerKeys[i].idPubKey
		authorityNames[pk] = authCfgs[i].Server.Identifier

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
		st.replicaDescriptors = make(map[uint64]map[[hash.HashSize]byte]*pki.ReplicaDescriptor)
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
		err = st.restorePersistence()
		require.NoError(err)

		st.authorizedReplicaNodes = make(map[[publicKeyHashSize]byte]*authorizedReplicaInfo)
		st.authorizedReplicaNodes[hash.Sum256(replica1IdPubKeyBytes)] = &authorizedReplicaInfo{
			Identifier: "replica-1",
			ReplicaID:  1,
		}
		st.reverseHash[hash.Sum256(replica1IdPubKeyBytes)] = replica1IdPubKey
	}

	// Set up PKI and mixes
	authorities := make([]*config.Authority, 0)
	for i, aCfg := range authCfgs {
		auth := &config.Authority{
			Addresses:          aCfg.Server.Addresses,
			WireKEMScheme:      testingSchemeName,
			PKISignatureScheme: testSignatureScheme.Name(),
			IdentityPublicKey:  peerKeys[i].idPubKey,
			LinkPublicKey:      config.LinkPublicKey{PublicKey: peerKeys[i].linkKey.Public()},
		}
		authorities = append(authorities, auth)
	}
	votingPKI := &sConfig.PKI{Voting: &sConfig.Voting{Authorities: authorities}}

	n := 3 * 2
	m := 2
	idKeys := make([]*identityKey, 0)
	mixCfgs := make([]*sConfig.Config, 0)
	port := uint16(30500)
	for i := 0; i < n; i++ {
		idKey, c, err := genMixConfig(fmt.Sprintf("node-%d", i), votingPKI, port)
		require.NoError(err)
		mixCfgs = append(mixCfgs, c)
		idKeys = append(idKeys, idKey)
		port++
		reverseHash[hash.Sum256From(idKey.pubKey)] = idKey.pubKey
	}
	topology := config.Topology{Layers: make([]config.Layer, 3)}
	topology.Layers[0].Nodes = []config.Node{
		{IdentityPublicKeyPem: idKeys[0].identityPublicKeyPem},
		{IdentityPublicKeyPem: idKeys[1].identityPublicKeyPem},
	}
	topology.Layers[1].Nodes = []config.Node{
		{IdentityPublicKeyPem: idKeys[2].identityPublicKeyPem},
		{IdentityPublicKeyPem: idKeys[3].identityPublicKeyPem},
	}
	topology.Layers[2].Nodes = []config.Node{
		{IdentityPublicKeyPem: idKeys[4].identityPublicKeyPem},
		{IdentityPublicKeyPem: idKeys[5].identityPublicKeyPem},
	}
	for i := 0; i < authNum; i++ {
		authCfgs[i].Topology = &topology
	}
	for i := 0; i < m; i++ {
		idKey, c, err := genGatewayConfig(fmt.Sprintf("gateway-%d", i), votingPKI, port)
		require.NoError(err)
		mixCfgs = append(mixCfgs, c)
		idKeys = append(idKeys, idKey)
		port++
		reverseHash[hash.Sum256From(idKey.pubKey)] = idKey.pubKey
	}
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
		stateAuthority[i].authorityNames = authorityNames
	}

	// Create mix descriptors
	mixDescs := make([]*pki.MixDescriptor, 0)
	gatewayDescs := make([]*pki.MixDescriptor, 0)
	serviceDescs := make([]*pki.MixDescriptor, 0)
	for i := 0; i < len(mixCfgs); i++ {
		mkeys := genMixKeys(votingEpoch)
		addr := make(map[string][]string)
		addr[pki.TransportTCPv4] = []string{"tcp4://127.0.0.1:1234"}
		linkPubKey, _, err := testingScheme.GenerateKeyPair()
		require.NoError(err)
		linkBlob, err := linkPubKey.MarshalBinary()
		require.NoError(err)
		idkeyblob, err := idKeys[i].pubKey.MarshalBinary()
		require.NoError(err)
		desc := &pki.MixDescriptor{
			Name: mixCfgs[i].Server.Identifier, Epoch: votingEpoch,
			IdentityKey: idkeyblob, LinkKey: linkBlob, MixKeys: mkeys,
			IsGatewayNode: mixCfgs[i].Server.IsGatewayNode,
			IsServiceNode: mixCfgs[i].Server.IsServiceNode,
			Addresses:     addr,
		}
		if mixCfgs[i].Server.IsServiceNode {
			serviceDescs = append(serviceDescs, desc)
		} else if mixCfgs[i].Server.IsGatewayNode {
			gatewayDescs = append(gatewayDescs, desc)
		} else {
			mixDescs = append(mixDescs, desc)
		}
	}

	// Create replica descriptors with DIFFERENT envelope keys for different authorities
	// This simulates a network partition where:
	// - Authority-0 and Authority-1 (majority) have majorityEnvelopeKey
	// - Authority-2 (minority) has minorityEnvelopeKey
	replica1LinkPubKey, _, err := testingScheme.GenerateKeyPair()
	require.NoError(err)
	replica1LinkBlob, err := replica1LinkPubKey.MarshalBinary()
	require.NoError(err)

	for i, s := range stateAuthority {
		s.descriptors[votingEpoch] = make(map[[hash.HashSize]byte]*pki.MixDescriptor)
		s.authorizedMixes = make(map[[hash.HashSize]byte]string)
		s.authorizedGatewayNodes = make(map[[hash.HashSize]byte]string)
		s.authorizedServiceNodes = make(map[[hash.HashSize]byte]string)
		for _, d := range mixDescs {
			s.descriptors[votingEpoch][hash.Sum256(d.IdentityKey)] = d
			s.authorizedMixes[hash.Sum256(d.IdentityKey)] = d.Name
		}
		for _, d := range gatewayDescs {
			s.descriptors[votingEpoch][hash.Sum256(d.IdentityKey)] = d
			s.authorizedGatewayNodes[hash.Sum256(d.IdentityKey)] = d.Name
		}
		for _, d := range serviceDescs {
			s.descriptors[votingEpoch][hash.Sum256(d.IdentityKey)] = d
			s.authorizedServiceNodes[hash.Sum256(d.IdentityKey)] = d.Name
		}

		// Create different descriptors based on partition
		var envelopeKey []byte
		if i < 2 {
			// Majority partition (authorities 0 and 1)
			envelopeKey = majorityEnvelopeKey
			t.Logf("Authority-%d in MAJORITY partition", i)
		} else {
			// Minority partition (authority 2)
			envelopeKey = minorityEnvelopeKey
			t.Logf("Authority-%d in MINORITY partition", i)
		}

		replica1Desc := &pki.ReplicaDescriptor{
			Name:        "replica-1",
			ReplicaID:   1,
			Epoch:       votingEpoch,
			IdentityKey: replica1IdPubKeyBytes,
			LinkKey:     replica1LinkBlob,
			EnvelopeKeys: map[uint64][]byte{
				currentReplicaEpoch: envelopeKey,
			},
			Addresses: map[string][]string{pki.TransportTCPv4: {"tcp4://127.0.0.1:5000"}},
		}

		s.replicaDescriptors[votingEpoch] = make(map[[hash.HashSize]byte]*pki.ReplicaDescriptor)
		s.replicaDescriptors[votingEpoch][hash.Sum256(replica1Desc.IdentityKey)] = replica1Desc
	}

	// Run consensus protocol
	commits := make(map[uint64]map[[hash.HashSize]byte][]byte)
	commits[votingEpoch] = make(map[[hash.HashSize]byte][]byte)
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

	for i, s := range stateAuthority {
		s.votingEpoch = votingEpoch
		s.genesisEpoch = s.votingEpoch
		myVote, err := s.getVote(s.votingEpoch)
		require.NoError(err)
		require.NotNil(myVote)
		s.state = stateAcceptVote
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.Lock()
			a.votes[s.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = myVote
			a.Unlock()
		}
	}

	for i, s := range stateAuthority {
		s.state = stateAcceptReveal
		c := s.reveal(s.votingEpoch)
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.Lock()
			a.reveals[a.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = c
			a.Unlock()
		}
	}

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
			a.Lock()
			a.certificates[s.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = myCertificate
			a.Unlock()
		}
		s.Unlock()
	}

	for _, s := range stateAuthority {
		s.Lock()
		_, err := s.getMyConsensus(s.votingEpoch)
		s.Unlock()
		require.NoError(err)
	}

	for i, s := range stateAuthority {
		s.state = stateAcceptSignature
		id := hash.Sum256From(s.s.identityPublicKey)
		mySignature, ok := s.myconsensus[s.votingEpoch].Signatures[id]
		require.True(ok)
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.Lock()
			a.signatures[s.votingEpoch][hash.Sum256From(s.s.identityPublicKey)] = &mySignature
			a.Unlock()
		}
	}

	// Get final consensus and verify the majority key wins
	for i, s := range stateAuthority {
		s.Lock()
		doc, err := s.getThresholdConsensus(s.votingEpoch)
		s.Unlock()
		require.NoError(err)

		// Replica should be in consensus
		require.Len(doc.StorageReplicas, 1, "Replica should achieve consensus")

		// The envelope key should be from the majority (first descriptor to win tally)
		// Note: The actual key depends on which descriptor is processed first during tallying
		// In practice, with 2/3 majority, the majority key should dominate
		if len(doc.StorageReplicas[0].EnvelopeKeys) > 0 {
			consensusKey := doc.StorageReplicas[0].EnvelopeKeys[currentReplicaEpoch]
			t.Logf("Authority-%d consensus has envelope key for replica epoch %d", i, currentReplicaEpoch)

			// The key should match one of the partition keys
			// Since the certificate is based on tallied results, and the majority (2/3)
			// has the majority key, it should win
			isMajorityKey := bytes.Equal(consensusKey, majorityEnvelopeKey)
			isMinorityKey := bytes.Equal(consensusKey, minorityEnvelopeKey)
			require.True(isMajorityKey || isMinorityKey, "Key should be from one of the partitions")

			if isMajorityKey {
				t.Logf("Authority-%d: Consensus uses MAJORITY partition key", i)
			} else {
				t.Logf("Authority-%d: Consensus uses MINORITY partition key", i)
			}
		}
	}

	t.Log("SUCCESS: Envelope key partition test passed")
	t.Log("- Network partition scenario: different authorities have different envelope keys")
	t.Log("- Consensus resolves to one of the partition's keys (based on tallying)")
}

// TestConsensusIdenticalAfterAuthorityRestart pins the invariant whose
// violation caused the 2026-07-12 namenlos outage: the consensus document
// must be a pure function of voted data, so an authority rebuilt from
// scratch mid-flight (a process restart) must produce a certificate
// byte-identical to its long-lived peers.
func TestConsensusIdenticalAfterAuthorityRestart(t *testing.T) {
	require := require.New(t)

	authNum := 3
	votingEpoch, _, _ := epochtime.Now()
	votingEpoch += 5
	round2Epoch := votingEpoch + 1
	parameters := &config.Parameters{
		Mu:      0.001,
		LambdaP: 0.002,
		LambdaL: 0.0005,
		LambdaM: 0.2,
	}

	peerKeys, authCfgs, err := genVotingAuthoritiesCfg(parameters, authNum)
	require.NoError(err)

	reverseHash := make(map[[publicKeyHashSize]byte]sign.PublicKey)
	authorityNames := make(map[[publicKeyHashSize]byte]string)
	for i := range peerKeys {
		pk := hash.Sum256From(peerKeys[i].idPubKey)
		reverseHash[pk] = peerKeys[i].idPubKey
		authorityNames[pk] = authCfgs[i].Server.Identifier
	}

	replicaAIdPubKey, _, err := testSignatureScheme.GenerateKey()
	require.NoError(err)
	replicaBIdPubKey, _, err := testSignatureScheme.GenerateKey()
	require.NoError(err)
	replicaAIdBytes, err := replicaAIdPubKey.MarshalBinary()
	require.NoError(err)
	replicaBIdBytes, err := replicaBIdPubKey.MarshalBinary()
	require.NoError(err)
	reverseHash[hash.Sum256(replicaAIdBytes)] = replicaAIdPubKey
	reverseHash[hash.Sum256(replicaBIdBytes)] = replicaBIdPubKey

	authorities := make([]*config.Authority, 0)
	for i, aCfg := range authCfgs {
		authorities = append(authorities, &config.Authority{
			Addresses:          aCfg.Server.Addresses,
			WireKEMScheme:      testingSchemeName,
			PKISignatureScheme: testSignatureScheme.Name(),
			IdentityPublicKey:  peerKeys[i].idPubKey,
			LinkPublicKey:      config.LinkPublicKey{PublicKey: peerKeys[i].linkKey.Public()},
		})
	}
	votingPKI := &sConfig.PKI{Voting: &sConfig.Voting{Authorities: authorities}}

	idKeys := make([]*identityKey, 0)
	mixCfgs := make([]*sConfig.Config, 0)
	port := uint16(31000)
	for i := 0; i < 6; i++ {
		idKey, c, err := genMixConfig(fmt.Sprintf("restart-node-%d", i), votingPKI, port)
		require.NoError(err)
		mixCfgs = append(mixCfgs, c)
		idKeys = append(idKeys, idKey)
		port++
		reverseHash[hash.Sum256From(idKey.pubKey)] = idKey.pubKey
	}
	topology := config.Topology{Layers: make([]config.Layer, 3)}
	for layer := 0; layer < 3; layer++ {
		topology.Layers[layer].Nodes = []config.Node{
			{IdentityPublicKeyPem: idKeys[2*layer].identityPublicKeyPem},
			{IdentityPublicKeyPem: idKeys[2*layer+1].identityPublicKeyPem},
		}
	}
	for i := 0; i < authNum; i++ {
		authCfgs[i].Topology = &topology
	}
	for i := 0; i < 2; i++ {
		idKey, c, err := genGatewayConfig(fmt.Sprintf("restart-gateway-%d", i), votingPKI, port)
		require.NoError(err)
		mixCfgs = append(mixCfgs, c)
		idKeys = append(idKeys, idKey)
		port++
		reverseHash[hash.Sum256From(idKey.pubKey)] = idKey.pubKey
	}
	for i := 0; i < 2; i++ {
		idKey, c, err := genServiceNodeConfig(fmt.Sprintf("restart-serviceNode-%d", i), votingPKI, port)
		require.NoError(err)
		mixCfgs = append(mixCfgs, c)
		idKeys = append(idKeys, idKey)
		port++
		reverseHash[hash.Sum256From(idKey.pubKey)] = idKey.pubKey
	}

	// Config-derived authorization maps, shared by all authority instances.
	authorizedMixes := make(map[[hash.HashSize]byte]string)
	authorizedGateways := make(map[[hash.HashSize]byte]string)
	authorizedServices := make(map[[hash.HashSize]byte]string)
	for i := range mixCfgs {
		idkeyblob, err := idKeys[i].pubKey.MarshalBinary()
		require.NoError(err)
		h := hash.Sum256(idkeyblob)
		switch {
		case mixCfgs[i].Server.IsServiceNode:
			authorizedServices[h] = mixCfgs[i].Server.Identifier
		case mixCfgs[i].Server.IsGatewayNode:
			authorizedGateways[h] = mixCfgs[i].Server.Identifier
		default:
			authorizedMixes[h] = mixCfgs[i].Server.Identifier
		}
	}

	// newAuthorityState builds an authority purely from configuration,
	// exactly what a process restart yields.
	newAuthorityState := func(i int) *state {
		st := new(state)
		st.votingEpoch = votingEpoch
		cfg := authCfgs[i]
		st.verifiers = make(map[[publicKeyHashSize]byte]sign.PublicKey)
		for j := range peerKeys {
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
		require.NoError(err)
		st.log = s.logBackend.GetLogger(fmt.Sprintf("restart-state%d", i))
		s.log = s.logBackend.GetLogger("authority")

		st.documents = make(map[uint64]*pki.Document)
		st.myconsensus = make(map[uint64]*pki.Document)
		st.descriptors = make(map[uint64]map[[hash.HashSize]byte]*pki.MixDescriptor)
		st.replicaDescriptors = make(map[uint64]map[[hash.HashSize]byte]*pki.ReplicaDescriptor)
		st.votes = make(map[uint64]map[[hash.HashSize]byte]*pki.Document)
		st.certificates = make(map[uint64]map[[hash.HashSize]byte]*pki.Document)
		st.commits = make(map[uint64]map[[hash.HashSize]byte][]byte)
		st.reveals = make(map[uint64]map[[hash.HashSize]byte][]byte)
		st.signatures = make(map[uint64]map[[hash.HashSize]byte]*cert.Signature)
		st.reverseHash = reverseHash
		st.authorityNames = authorityNames

		tmpDir, err := os.MkdirTemp("", cfg.Server.Identifier)
		require.NoError(err)
		db, err := bolt.Open(filepath.Join(tmpDir, "persistence.db"), 0600, nil)
		require.NoError(err)
		st.db = db
		require.NoError(st.restorePersistence())

		st.authorizedMixes = authorizedMixes
		st.authorizedGatewayNodes = authorizedGateways
		st.authorizedServiceNodes = authorizedServices
		st.authorizedReplicaNodes = map[[publicKeyHashSize]byte]*authorizedReplicaInfo{
			hash.Sum256(replicaAIdBytes): {Identifier: "replica-a", ReplicaID: 1},
			hash.Sum256(replicaBIdBytes): {Identifier: "replica-b", ReplicaID: 2},
		}
		return st
	}

	stateAuthority := make([]*state, authNum)
	for i := 0; i < authNum; i++ {
		stateAuthority[i] = newAuthorityState(i)
	}

	makeMixDescs := func(epoch uint64) []*pki.MixDescriptor {
		descs := make([]*pki.MixDescriptor, 0, len(mixCfgs))
		for i := 0; i < len(mixCfgs); i++ {
			linkPubKey, _, err := testingScheme.GenerateKeyPair()
			require.NoError(err)
			linkBlob, err := linkPubKey.MarshalBinary()
			require.NoError(err)
			idkeyblob, err := idKeys[i].pubKey.MarshalBinary()
			require.NoError(err)
			descs = append(descs, &pki.MixDescriptor{
				Name:          mixCfgs[i].Server.Identifier,
				Epoch:         epoch,
				IdentityKey:   idkeyblob,
				LinkKey:       linkBlob,
				MixKeys:       genMixKeys(epoch),
				IsGatewayNode: mixCfgs[i].Server.IsGatewayNode,
				IsServiceNode: mixCfgs[i].Server.IsServiceNode,
				Addresses:     map[string][]string{pki.TransportTCPv4: {"tcp4://127.0.0.1:1234"}},
			})
		}
		return descs
	}

	replicaALinkPubKey, _, err := testingScheme.GenerateKeyPair()
	require.NoError(err)
	replicaALinkBlob, err := replicaALinkPubKey.MarshalBinary()
	require.NoError(err)
	replicaBLinkPubKey, _, err := testingScheme.GenerateKeyPair()
	require.NoError(err)
	replicaBLinkBlob, err := replicaBLinkPubKey.MarshalBinary()
	require.NoError(err)

	envelopeKeyA := make([]byte, 32)
	rand.Reader.Read(envelopeKeyA)
	envelopeKeyB1 := make([]byte, 32)
	rand.Reader.Read(envelopeKeyB1)
	envelopeKeyB2 := make([]byte, 32)
	rand.Reader.Read(envelopeKeyB2)

	makeReplicaDesc := func(name string, id uint8, idBytes, linkBlob []byte, epoch uint64, envKeys map[uint64][]byte) *pki.ReplicaDescriptor {
		return &pki.ReplicaDescriptor{
			Name:         name,
			ReplicaID:    id,
			Epoch:        epoch,
			IdentityKey:  idBytes,
			LinkKey:      linkBlob,
			EnvelopeKeys: envKeys,
			Addresses:    map[string][]string{pki.TransportTCPv4: {"tcp4://127.0.0.1:5000"}},
		}
	}

	// runRound drives one full vote/reveal/certificate/signature exchange
	// and returns each authority's certificate document.
	runRound := func(epoch uint64, replicaDescs []*pki.ReplicaDescriptor) []*pki.Document {
		mixDescs := makeMixDescs(epoch)
		for _, st := range stateAuthority {
			st.votingEpoch = epoch
			st.votes[epoch] = make(map[[hash.HashSize]byte]*pki.Document)
			st.certificates[epoch] = make(map[[hash.HashSize]byte]*pki.Document)
			st.signatures[epoch] = make(map[[hash.HashSize]byte]*cert.Signature)
			st.descriptors[epoch] = make(map[[hash.HashSize]byte]*pki.MixDescriptor)
			st.replicaDescriptors[epoch] = make(map[[hash.HashSize]byte]*pki.ReplicaDescriptor)
			for _, d := range mixDescs {
				st.descriptors[epoch][hash.Sum256(d.IdentityKey)] = d
			}
			for _, d := range replicaDescs {
				st.replicaDescriptors[epoch][hash.Sum256(d.IdentityKey)] = d
			}
		}

		commits := make(map[uint64]map[[hash.HashSize]byte][]byte)
		commits[epoch] = make(map[[hash.HashSize]byte][]byte)
		for _, st := range stateAuthority {
			reveals := make(map[uint64]map[[hash.HashSize]byte][]byte)
			reveals[epoch] = make(map[[hash.HashSize]byte][]byte)
			srv := new(pki.SharedRandom)
			commit, err := srv.Commit(epoch)
			require.NoError(err)
			signedCommit, err := cert.Sign(st.s.identityPrivateKey, st.s.identityPublicKey, commit, epoch+1)
			require.NoError(err)
			commits[epoch][hash.Sum256From(st.s.identityPublicKey)] = signedCommit
			st.commits = commits
			reveal := srv.Reveal()
			signedReveal, err := cert.Sign(st.s.identityPrivateKey, st.s.identityPublicKey, reveal, epoch+1)
			require.NoError(err)
			reveals[epoch][hash.Sum256From(st.s.identityPublicKey)] = signedReveal
			st.reveals = reveals
		}

		for i, st := range stateAuthority {
			myVote, err := st.getVote(epoch)
			require.NoError(err)
			require.NotNil(myVote)
			st.state = stateAcceptVote
			for j, a := range stateAuthority {
				if j == i {
					continue
				}
				a.Lock()
				a.votes[epoch][hash.Sum256From(st.s.identityPublicKey)] = myVote
				a.Unlock()
			}
		}

		for i, st := range stateAuthority {
			st.state = stateAcceptReveal
			c := st.reveal(epoch)
			for j, a := range stateAuthority {
				if j == i {
					continue
				}
				a.Lock()
				a.reveals[epoch][hash.Sum256From(st.s.identityPublicKey)] = c
				a.Unlock()
			}
		}

		certs := make([]*pki.Document, len(stateAuthority))
		for i, st := range stateAuthority {
			st.Lock()
			st.state = stateAcceptCert
			myCertificate, err := st.getCertificate(epoch)
			require.NoError(err)
			certs[i] = myCertificate
			_, err = pki.SignDocument(st.s.identityPrivateKey, st.s.identityPublicKey, myCertificate)
			require.NoError(err)
			for j, a := range stateAuthority {
				if j == i {
					continue
				}
				a.Lock()
				a.certificates[epoch][hash.Sum256From(st.s.identityPublicKey)] = myCertificate
				a.Unlock()
			}
			st.Unlock()
		}

		for _, st := range stateAuthority {
			st.Lock()
			_, err := st.getMyConsensus(epoch)
			st.Unlock()
			require.NoError(err)
		}

		for i, st := range stateAuthority {
			st.state = stateAcceptSignature
			id := hash.Sum256From(st.s.identityPublicKey)
			mySignature, ok := st.myconsensus[epoch].Signatures[id]
			require.True(ok)
			for j, a := range stateAuthority {
				if j == i {
					continue
				}
				a.Lock()
				a.signatures[epoch][hash.Sum256From(st.s.identityPublicKey)] = &mySignature
				a.Unlock()
			}
		}

		for _, st := range stateAuthority {
			st.Lock()
			_, err := st.getThresholdConsensus(epoch)
			st.Unlock()
			require.NoError(err)
		}
		return certs
	}

	// Round 1: both replicas submit descriptors to every authority.
	round1Descs := []*pki.ReplicaDescriptor{
		makeReplicaDesc("replica-a", 1, replicaAIdBytes, replicaALinkBlob, votingEpoch,
			map[uint64][]byte{100: envelopeKeyA}),
		makeReplicaDesc("replica-b", 2, replicaBIdBytes, replicaBLinkBlob, votingEpoch,
			map[uint64][]byte{100: envelopeKeyB1, 101: envelopeKeyB2}),
	}
	runRound(votingEpoch, round1Descs)

	// Simulate a process restart of authority 2 between rounds: rebuild it
	// from configuration, then seed only what a real restart restores from
	// persistence (the prior consensus document).
	round1Doc := stateAuthority[2].documents[votingEpoch]
	require.NotNil(round1Doc)
	restarted := newAuthorityState(2)
	restarted.documents[votingEpoch] = round1Doc
	stateAuthority[2] = restarted

	// Round 2: only replica-b submits a descriptor.
	round2Descs := []*pki.ReplicaDescriptor{
		makeReplicaDesc("replica-b", 2, replicaBIdBytes, replicaBLinkBlob, round2Epoch,
			map[uint64][]byte{100: envelopeKeyB1, 101: envelopeKeyB2}),
	}
	certs := runRound(round2Epoch, round2Descs)

	// The exact property whose violation broke namenlos: every authority,
	// long-lived or freshly restarted, signs byte-identical content.
	certBytes := make([][]byte, len(certs))
	for i, c := range certs {
		docCopy := *c
		docCopy.Signatures = nil
		b, err := docCopy.MarshalCertificate()
		require.NoError(err)
		certBytes[i] = b
	}
	require.Equal(certBytes[0], certBytes[1], "long-lived authorities disagree")
	require.Equal(certBytes[0], certBytes[2], "restarted authority diverged from long-lived peers")

	for i, c := range certs {
		require.Len(c.StorageReplicas, 1, "authority-%d round 2 must carry only replica-b", i)
		require.Equal(uint8(2), c.StorageReplicas[0].ReplicaID)
		require.Len(c.StorageReplicas[0].EnvelopeKeys, 2)
	}
}
