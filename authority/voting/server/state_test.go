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
	"golang.org/x/crypto/sha3"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/crypto/cert"
	"github.com/katzenpost/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/pem"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/crypto/sign"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire"
	sConfig "github.com/katzenpost/katzenpost/server/config"
)

func TestSharedRandomVerify(t *testing.T) {
	require := require.New(t)
	srv := new(SharedRandom)
	commit, err := srv.Commit(1234)
	require.NoError(err, "wtf")
	require.True(len(commit) == pki.SharedRandomLength)
	srv.SetCommit(commit)
	require.True(bytes.Equal(commit, srv.GetCommit()))
	t.Logf("commit %v", commit)
	require.True(bytes.Equal(commit, srv.GetCommit()))
	reveal := srv.Reveal()
	t.Logf("h(reveal) %v", sha3.Sum256(reveal))
	t.Logf("reveal %v", reveal)
	t.Logf("len(reveal): %v", len(reveal))
	require.True(len(reveal) == pki.SharedRandomLength)
	require.True(srv.Verify(reveal))
}

func TestSharedRandomCommit(t *testing.T) {
	require := require.New(t)
	srv := new(SharedRandom)
	commit, err := srv.Commit(1234)
	require.NoError(err, "wtf")
	require.True(len(commit) == pki.SharedRandomLength)
}

func TestSharedRandomSetCommit(t *testing.T) {
	require := require.New(t)
	srv := new(SharedRandom)
	commit, err := srv.Commit(1234)
	require.NoError(err, "wtf")
	srv.SetCommit(commit)
	require.True(bytes.Equal(commit, srv.GetCommit()))
}

func TestVote(t *testing.T) {
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
		st.verifiers = make(map[[publicKeyHashSize]byte]cert.Verifier)
		for i, _ := range cfg.Authorities {
			st.verifiers[peerKeys[i].idPubKey.Sum256()] = cert.Verifier(peerKeys[i].idPubKey)
		}
		// add this authoritys key to verifiers
		st.verifiers[peerKeys[i].idPubKey.Sum256()] = cert.Verifier(peerKeys[i].idPubKey)
		st.threshold = len(st.verifiers)/2 + 1
		st.dissenters = len(cfg.Authorities)/2 - 1

		s := &Server{
			cfg:                cfg,
			identityPrivateKey: peerKeys[i].idKey,
			identityPublicKey:  peerKeys[i].idPubKey,
			fatalErrCh:         make(chan error),
			haltedCh:           make(chan interface{}),
		}
		reverseHash[peerKeys[i].idPubKey.Sum256()] = peerKeys[i].idPubKey

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

		st.documents = make(map[uint64]*document)
		st.descriptors = make(map[uint64]map[[sign.PublicKeyHashSize]byte]*descriptor)
		st.votes = make(map[uint64]map[[sign.PublicKeyHashSize]byte]*document)
		st.votes[votingEpoch] = make(map[[sign.PublicKeyHashSize]byte]*document)
		st.certificates = make(map[uint64]map[[sign.PublicKeyHashSize]byte][]byte)
		st.certificates[st.votingEpoch] = make(map[[sign.PublicKeyHashSize]byte][]byte)
		st.reveals = make(map[uint64]map[[sign.PublicKeyHashSize]byte][]byte)
		st.reveals[st.votingEpoch] = make(map[[sign.PublicKeyHashSize]byte][]byte)
		st.reverseHash = make(map[[publicKeyHashSize]byte]sign.PublicKey)
		stateAuthority[i] = st
		tmpDir, err := os.MkdirTemp("", cfg.Identifier)
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
	peers := make([]*config.Authority, 0)
	for i, peer := range authCfgs {
		require.NoError(err)
		p := &config.Authority{Addresses: peer.Addresses,
			IdentityPublicKeyPem: peerKeys[i].identityPublicKeyPem,
			LinkPublicKeyPem:     peerKeys[i].linkPublicKeyPem,
		}
		if len(peer.Addresses) == 0 {
			panic("wtf")
		}
		peers = append(peers, p)
	}
	votingPKI := &sConfig.PKI{Voting: &sConfig.Voting{Peers: peers}}

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
		reverseHash[idKey.pubKey.Sum256()] = idKey.pubKey
	}

	// generate a Topology section
	topology := config.Topology{Layers: make([]config.Layer, 3)}
	topology.Layers[0].Nodes = []config.Node{config.Node{IdentityPublicKeyPem: pem.ToPEMString(idKeys[0].pubKey)},
		config.Node{IdentityPublicKeyPem: pem.ToPEMString(idKeys[1].pubKey)}}
	topology.Layers[1].Nodes = []config.Node{config.Node{IdentityPublicKeyPem: pem.ToPEMString(idKeys[2].pubKey)},
		config.Node{IdentityPublicKeyPem: pem.ToPEMString(idKeys[3].pubKey)}}
	topology.Layers[2].Nodes = []config.Node{config.Node{IdentityPublicKeyPem: pem.ToPEMString(idKeys[4].pubKey)},
		config.Node{IdentityPublicKeyPem: pem.ToPEMString(idKeys[5].pubKey)}}

	// generate a Topology section
	authCfgs[0].Topology = &topology
	authCfgs[1].Topology = &topology
	authCfgs[2].Topology = &topology

	// generate providers
	for i := 0; i < m; i++ {
		idKey, c, err := genProviderConfig(fmt.Sprintf("provider-%d", i), votingPKI, port)
		require.NoError(err)
		mixCfgs = append(mixCfgs, c)
		idKeys = append(idKeys, idKey)
		port++
		reverseHash[idKey.pubKey.Sum256()] = idKey.pubKey
	}

	for i := 0; i < len(stateAuthority); i++ {
		stateAuthority[i].reverseHash = reverseHash
	}

	// post descriptors from nodes
	mixDescs := make([]*descriptor, 0)
	providerDescs := make([]*descriptor, 0)
	for i := 0; i < len(mixCfgs); i++ {
		mkeys := genMixKeys(votingEpoch)
		addr := make(map[pki.Transport][]string)
		addr[pki.TransportTCPv4] = []string{"127.0.0.1:1234"}
		l := uint8(0)
		if mixCfgs[i].Server.IsProvider {
			l = 255
		}

		linkKey := wire.DefaultScheme.GenerateKeypair(rand.Reader)

		desc := &pki.MixDescriptor{
			Name:        mixCfgs[i].Server.Identifier,
			Epoch:       votingEpoch,
			IdentityKey: idKeys[i].pubKey,
			LinkKey:     linkKey.PublicKey(),
			MixKeys:     mkeys,
			Layer:       l,
			Addresses:   addr,
		}

		err = pki.IsDescriptorWellFormed(desc, votingEpoch)
		require.NoError(err)
		// Make a serialized + signed + serialized descriptor.
		signed, err := pki.SignDescriptor(idKeys[i].privKey, idKeys[i].pubKey, desc)
		require.NoError(err)

		if mixCfgs[i].Server.IsProvider {
			providerDescs = append(mixDescs, &descriptor{raw: signed, desc: desc})
		} else {
			mixDescs = append(mixDescs, &descriptor{raw: signed, desc: desc})
		}
	}

	// populate the authorities with the descriptors
	for _, s := range stateAuthority {
		s.descriptors[votingEpoch] = make(map[[sign.PublicKeyHashSize]byte]*descriptor)
		s.authorizedMixes = make(map[[sign.PublicKeyHashSize]byte]bool)
		s.authorizedProviders = make(map[[sign.PublicKeyHashSize]byte]string)
		for _, d := range mixDescs {
			s.descriptors[votingEpoch][d.desc.IdentityKey.Sum256()] = d
			s.authorizedMixes[d.desc.IdentityKey.Sum256()] = true
		}
		for _, d := range providerDescs {
			s.descriptors[votingEpoch][d.desc.IdentityKey.Sum256()] = d
			s.authorizedProviders[d.desc.IdentityKey.Sum256()] = d.desc.Name
		}
	}

	// exchange votes
	for i, s := range stateAuthority {
		s.votingEpoch = votingEpoch
		s.genesisEpoch = s.votingEpoch
		myVote, err := s.vote(s.votingEpoch)
		require.NoError(err)
		require.NotNil(myVote)
		require.NotNil(myVote.doc)
		doc, err := pki.VerifyAndParseDocument(myVote.raw, s.s.identityPublicKey)
		require.NoError(err)
		myVote.doc = doc
		s.state = stateAcceptVote
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.votes[s.votingEpoch][s.s.identityPublicKey.Sum256()] = myVote
		}
	}

	// exchange reveals
	for i, s := range stateAuthority {
		s.state = stateAcceptReveal
		c := s.reveal(s.votingEpoch)
		r, err := cert.Verify(s.s.IdentityKey(), c)
		require.NoError(err)
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.reveals[s.votingEpoch][s.s.identityPublicKey.Sum256()] = r
			t.Logf("%s sent %s reveal", authCfgs[i].Identifier, authCfgs[j].Identifier)
		}

	}

	// create a consensus and exchange signatures
	for i, s := range stateAuthority {
		s.state = stateAcceptSignature
		myCertificate, err := s.tabulate(s.votingEpoch)
		require.NoError(err)
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.certificates[s.votingEpoch][s.s.identityPublicKey.Sum256()] = myCertificate
		}

	}

	// save the consensus
	for i, s := range stateAuthority {
		consensus := s.consense(s.votingEpoch)
		require.NotNil(consensus, "auth-%d failed to generate consensus", i)
	}

	// verify that each authority produced the same output
	docs := make([][]byte, len(stateAuthority))
	for i, s := range stateAuthority {
		d, _ := s.documents[s.votingEpoch]
		if d == nil {
			t.Logf("i %d failed", i)
			continue
		}
		docs[i] = d.raw
		if i == 0 {
			continue
		}

		a := []byte{}
		b := []byte{}
		copy(a, docs[i-1])
		copy(b, d.raw)
		require.True(bytes.Equal(a, b))
	}
}

type peerKeys struct {
	linkKey               wire.PrivateKey
	idKey                 sign.PrivateKey
	idPubKey              sign.PublicKey
	identityPublicKeyPem  string
	identityPrivateKeyPem string
	linkPublicKeyPem      string
	datadir               string
}

func genVotingAuthoritiesCfg(parameters *config.Parameters, numAuthorities int) ([]peerKeys, []*config.Config, error) {
	configs := []*config.Config{}
	basePort := 30000
	lastPort := basePort + 1

	myPeerKeys := make([]peerKeys, numAuthorities)

	// initial generation of key material for each authority
	peersMap := make(map[[sign.PublicKeyHashSize]byte]*config.Authority)
	for i := 0; i < numAuthorities; i++ {
		cfg := new(config.Config)
		cfg.Logging = &config.Logging{Disable: false, File: "", Level: "DEBUG"}
		cfg.Parameters = parameters

		datadir, err := os.MkdirTemp("", fmt.Sprintf("auth_%d", i))
		if err != nil {
			panic(err)
		}

		cfg.Identifier = fmt.Sprintf("authority-%v", i)
		cfg.Addresses = []string{fmt.Sprintf("127.0.0.1:%d", lastPort)}
		cfg.DataDir =  datadir
		lastPort += 1

		scheme := wire.DefaultScheme
		linkKey := scheme.GenerateKeypair(rand.Reader)
		linkPublicKeyPem := pem.ToPEMString(linkKey.PublicKey())

		idKey, idPubKey := cert.Scheme.NewKeypair()
		identityPublicKeyPem := pem.ToPEMString(idPubKey)

		myPeerKeys[i] = peerKeys{
			linkKey:              linkKey,
			idKey:                idKey,
			idPubKey:             idPubKey,
			identityPublicKeyPem: identityPublicKeyPem,
			linkPublicKeyPem:     linkPublicKeyPem,
			datadir:              datadir,
		}

		cfg.Debug = &config.Debug{
			Layers:           3,
			MinNodesPerLayer: 1,
			GenerateOnly:     false,
		}
		configs = append(configs, cfg)
		authorityPeer := &config.Authority{
			IdentityPublicKeyPem: identityPublicKeyPem,
			LinkPublicKeyPem:     linkPublicKeyPem,
			Addresses:            cfg.Addresses,
		}
		peersMap[idPubKey.Sum256()] = authorityPeer
	}

	// tell each authority about it's peers
	for i := 0; i < numAuthorities; i++ {
		peers := []*config.Authority{}
		for id, peer := range peersMap {
			idHash := myPeerKeys[i].idPubKey.Sum256()
			if !bytes.Equal(id[:], idHash[:]) {
				peers = append(peers, peer)
			}
		}
		configs[i].Authorities = peers
	}
	return myPeerKeys, configs, nil
}

func genProviderConfig(name string, pki *sConfig.PKI, port uint16) (*identityKey, *sConfig.Config, error) {
	const serverLogFile = ""

	cfg := new(sConfig.Config)

	// Server section.
	cfg.Server = new(sConfig.Server)
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
	cfg.Server.IsProvider = true

	// Debug section.
	cfg.Debug = new(sConfig.Debug)

	// Generate keys
	idKey, idPubKey := cert.Scheme.NewKeypair()

	scheme := wire.DefaultScheme
	linkKey := scheme.GenerateKeypair(rand.Reader)
	linkPublicKeyPem := "link.public.pem"

	idprivkeypem := filepath.Join(datadir, "identity.private.pem")

	err = pem.ToFile(idprivkeypem, idKey)
	if err != nil {
		return nil, nil, err
	}

	err = pem.ToFile(filepath.Join(datadir, "identity.public.pem"), idPubKey)
	if err != nil {
		return nil, nil, err
	}

	err = pem.ToFile(filepath.Join(datadir, "link.private.pem"), linkKey)
	if err != nil {
		return nil, nil, err
	}

	err = pem.ToFile(filepath.Join(datadir, linkPublicKeyPem), linkKey.PublicKey())
	if err != nil {
		return nil, nil, err
	}

	// PKI section.
	cfg.PKI = pki

	// Enable the thwack interface.
	cfg.Management = new(sConfig.Management)
	cfg.Management.Enable = true

	cfg.Provider = new(sConfig.Provider)

	echoCfg := new(sConfig.Kaetzchen)
	echoCfg.Capability = "echo"
	echoCfg.Endpoint = "+echo"
	cfg.Provider.Kaetzchen = append(cfg.Provider.Kaetzchen, echoCfg)
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

	// Server section.
	cfg.Server = new(sConfig.Server)
	cfg.Server.Identifier = name
	cfg.Server.Addresses = []string{fmt.Sprintf("127.0.0.1:%d", port)}
	cfg.Server.IsProvider = false

	datadir, err := os.MkdirTemp("", fmt.Sprintf("mix_%s", name))
	if err != nil {
		panic(err)
	}

	cfg.Server.DataDir = datadir

	// Debug section.
	cfg.Debug = new(sConfig.Debug)

	// Generate keys
	idKey, idPubKey := cert.Scheme.NewKeypair()

	scheme := wire.DefaultScheme
	linkKey := scheme.GenerateKeypair(rand.Reader)
	linkPublicKeyPem := "link.public.pem"

	idprivkeypem := filepath.Join(datadir, "identity.private.pem")
	idpubkeypem := filepath.Join(datadir, "identity.public.pem")

	err = pem.ToFile(idprivkeypem, idKey)
	if err != nil {
		return nil, nil, err
	}

	err = pem.ToFile(idpubkeypem, idPubKey)
	if err != nil {
		return nil, nil, err
	}

	err = pem.ToFile(filepath.Join(datadir, "link.private.pem"), linkKey)
	if err != nil {
		return nil, nil, err
	}

	err = pem.ToFile(filepath.Join(datadir, linkPublicKeyPem), linkKey.PublicKey())
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
func genMixKeys(votingEpoch uint64) map[uint64]*ecdh.PublicKey {
	mixKeys := make(map[uint64]*ecdh.PublicKey)
	for i := votingEpoch; i < votingEpoch+2; i++ {
		idKey, _ := ecdh.NewKeypair(rand.Reader)
		mixKeys[i] = idKey.PublicKey()
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
