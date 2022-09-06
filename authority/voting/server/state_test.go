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

// +build test

package server

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	_ "net/http/pprof"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/sha3"

	"github.com/katzenpost/katzenpost/authority/internal/s11n"
	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/crypto/cert"
	"github.com/katzenpost/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	sConfig "github.com/katzenpost/katzenpost/server/config"
)

func TestSharedRandomVerify(t *testing.T) {
	assert := assert.New(t)
	srv := new(SharedRandom)
	commit, err := srv.Commit(1234)
	assert.NoError(err, "wtf")
	assert.True(len(commit) == s11n.SharedRandomLength)
	srv.SetCommit(commit)
	assert.True(bytes.Equal(commit, srv.GetCommit()))
	t.Logf("commit %v", commit)
	assert.True(bytes.Equal(commit, srv.GetCommit()))
	reveal := srv.Reveal()
	t.Logf("h(reveal) %v", sha3.Sum256(reveal))
	t.Logf("reveal %v", reveal)
	t.Logf("len(reveal): %v", len(reveal))
	assert.True(len(reveal) == s11n.SharedRandomLength)
	assert.True(srv.Verify(reveal))
}

func TestSharedRandomCommit(t *testing.T) {
	assert := assert.New(t)
	srv := new(SharedRandom)
	commit, err := srv.Commit(1234)
	assert.NoError(err, "wtf")
	assert.True(len(commit) == s11n.SharedRandomLength)
}

func TestSharedRandomSetCommit(t *testing.T) {
	assert := assert.New(t)
	srv := new(SharedRandom)
	commit, err := srv.Commit(1234)
	assert.NoError(err, "wtf")
	srv.SetCommit(commit)
	assert.True(bytes.Equal(commit, srv.GetCommit()))
}

func TestVote(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// instantiate states
	n := 3
	stateAuthority := make([]*state, n)
	votingEpoch := uint64(42)
	parameters := &config.Parameters{
		SendRatePerMinute: 100, Mu: 0.001, MuMaxDelay: 9000,
		LambdaP: 0.002, LambdaPMaxDelay: 9000,
		LambdaL: 0.0005, LambdaLMaxDelay: 9000,
		LambdaD: 0.0005, LambdaDMaxDelay: 9000,
		LambdaM: 0.2, LambdaMMaxDelay: 9000,
	}

	authCfgs, err := genVotingAuthoritiesCfg(parameters, n)
	require.NoError(err)

	// set up authorities from configuration
	for i := 0; i < n; i++ {
		st := new(state)
		st.votingEpoch = votingEpoch
		cfg := authCfgs[i]
		st.verifiers = make([]cert.Verifier, len(cfg.Authorities)+1)
		for i, auth := range cfg.Authorities {
			st.verifiers[i] = cert.Verifier(auth.IdentityPublicKey)
		}
		st.verifiers[len(cfg.Authorities)] = cert.Verifier(cfg.Debug.IdentityKey.PublicKey())
		st.threshold = len(st.verifiers)/2 + 1
		st.dissenters = len(cfg.Authorities)/2 - 1

		s := &Server{
			cfg:         cfg,
			identityKey: cfg.Debug.IdentityKey,
			fatalErrCh:  make(chan error),
			haltedCh:    make(chan interface{}),
		}
		go func() {
			for {
				select {
				case err := <-s.fatalErrCh:
					assert.NoError(err)
				case _, ok := <-s.haltedCh:
					if !ok {
						return
					}
				}
			}
		}()
		st.s = s
		s.logBackend, err = log.New(cfg.Logging.File, s.cfg.Logging.Level, s.cfg.Logging.Disable)
		st.log = s.logBackend.GetLogger("state")
		if err == nil {
			s.log = s.logBackend.GetLogger("authority")
		}

		st.documents = make(map[uint64]*document)
		st.descriptors = make(map[uint64]map[[eddsa.PublicKeySize]byte]*descriptor)
		st.votes = make(map[uint64]map[[eddsa.PublicKeySize]byte]*document)
		st.votes[votingEpoch] = make(map[[eddsa.PublicKeySize]byte]*document)
		st.certificates = make(map[uint64]map[[eddsa.PublicKeySize]byte][]byte)
		st.certificates[st.votingEpoch] = make(map[[eddsa.PublicKeySize]byte][]byte)
		st.reveals = make(map[uint64]map[[eddsa.PublicKeySize]byte][]byte)
		st.reveals[st.votingEpoch] = make(map[[eddsa.PublicKeySize]byte][]byte)
		stateAuthority[i] = st
		tmpDir, err := ioutil.TempDir("", cfg.Authority.Identifier)
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
	peers := make([]*sConfig.Peer, 0)
	for _, peer := range authCfgs {
		idKey, err := peer.Debug.IdentityKey.PublicKey().MarshalText()
		require.NoError(err)

		linkKey, err := peer.Debug.LinkKey.PublicKey().MarshalText()
		require.NoError(err)
		p := &sConfig.Peer{Addresses: peer.Authority.Addresses,
			IdentityPublicKey: string(idKey),
			LinkPublicKey:     string(linkKey),
		}
		if len(peer.Authority.Addresses) == 0 {
			panic("wtf")
		}
		peers = append(peers, p)
	}
	votingPKI := &sConfig.PKI{Voting: &sConfig.Voting{Peers: peers}}

	// generate mixes
	n = 3 * 2 // 3 layer, 2 nodes per layer
	m := 2    // 2 providers
	mixCfgs := make([]*sConfig.Config, 0)
	port := uint16(30000)
	for i := 0; i < n; i++ {
		c, err := genMixConfig(fmt.Sprintf("node-%d", i), votingPKI, port)
		require.NoError(err)
		mixCfgs = append(mixCfgs, c)
		port++
	}

	// generate a Topology section
	topology := config.Topology{Layers: make([]config.Layer, 3)}
	topology.Layers[0].Nodes = []config.Node{config.Node{IdentityKey: mixCfgs[0].Debug.IdentityKey.PublicKey()},
		config.Node{IdentityKey: mixCfgs[1].Debug.IdentityKey.PublicKey()}}
	topology.Layers[1].Nodes = []config.Node{config.Node{IdentityKey: mixCfgs[2].Debug.IdentityKey.PublicKey()},
		config.Node{IdentityKey: mixCfgs[3].Debug.IdentityKey.PublicKey()}}
	topology.Layers[2].Nodes = []config.Node{config.Node{IdentityKey: mixCfgs[4].Debug.IdentityKey.PublicKey()},
		config.Node{IdentityKey: mixCfgs[5].Debug.IdentityKey.PublicKey()}}

	// generate a conflicting Topology
	// generate a Topology section
	topology2 := config.Topology{Layers: make([]config.Layer, 3)}
	topology2.Layers[0].Nodes = []config.Node{config.Node{IdentityKey: mixCfgs[0].Debug.IdentityKey.PublicKey()},
		config.Node{IdentityKey: mixCfgs[1].Debug.IdentityKey.PublicKey()}}
	topology2.Layers[1].Nodes = []config.Node{config.Node{IdentityKey: mixCfgs[2].Debug.IdentityKey.PublicKey()},
		config.Node{IdentityKey: mixCfgs[3].Debug.IdentityKey.PublicKey()}}
	topology2.Layers[2].Nodes = []config.Node{config.Node{IdentityKey: mixCfgs[5].Debug.IdentityKey.PublicKey()},
		config.Node{IdentityKey: mixCfgs[4].Debug.IdentityKey.PublicKey()}}

	// one auth uses the conflicting topology, so we shall expect consensus with 2/3
	authCfgs[0].Topology = &topology
	authCfgs[1].Topology = &topology2
	authCfgs[2].Topology = &topology

	// generate providers
	for i := 0; i < m; i++ {
		c, err := genProviderConfig(fmt.Sprintf("provider-%d", i), votingPKI, port)
		require.NoError(err)
		mixCfgs = append(mixCfgs, c)
		port++
	}

	// post descriptors from nodes
	mixDescs := make([]*descriptor, 0)
	for _, mixCfg := range mixCfgs {
		mkeys := genMixKeys(votingEpoch)
		addr := make(map[pki.Transport][]string)
		addr[pki.TransportTCPv4] = []string{"127.0.0.1:1234"}
		l := uint8(0)
		if mixCfg.Server.IsProvider {
			l = 255
		}

		linkKey, err := ecdh.NewKeypair(rand.Reader)
		if err != nil {
			panic(err)
		}

		desc := &pki.MixDescriptor{
			Name:        mixCfg.Server.Identifier,
			IdentityKey: mixCfg.Debug.IdentityKey.PublicKey(),
			LinkKey:     linkKey.PublicKey(),
			MixKeys:     mkeys,
			Layer:       l,
			Addresses:   addr,
		}

		err = s11n.IsDescriptorWellFormed(desc, votingEpoch)
		require.NoError(err)
		// Make a serialized + signed + serialized descriptor.
		signed, err := s11n.SignDescriptor(mixCfg.Debug.IdentityKey, desc)
		require.NoError(err)
		mixDescs = append(mixDescs, &descriptor{raw: signed, desc: desc})
	}

	// populate the authorities with the descriptors
	for _, s := range stateAuthority {
		s.descriptors[votingEpoch] = make(map[[eddsa.PublicKeySize]byte]*descriptor)
		for _, d := range mixDescs {
			var fu [eddsa.PublicKeySize]byte
			copy(fu[:], d.desc.IdentityKey.Bytes())
			s.descriptors[votingEpoch][fu] = d
		}
	}

	// exchange votes
	for i, s := range stateAuthority {
		t.Logf("s.s.IdentityKey: %s", s.s.IdentityKey())
		s.votingEpoch = votingEpoch
		s.genesisEpoch = s.votingEpoch
		myVote, err := s.vote(s.votingEpoch)
		require.NoError(err)
		require.NotNil(myVote)
		require.NotNil(myVote.doc)
		doc, err := s11n.VerifyAndParseDocument(myVote.raw, s.s.identityKey.PublicKey())
		require.NoError(err)
		myVote.doc = doc
		s.state = stateAcceptVote
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.votes[s.votingEpoch][s.identityPubKey()] = myVote
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
			a.reveals[s.votingEpoch][s.identityPubKey()] = r
			t.Logf("%s sent %s reveal", authCfgs[i].Authority.Identifier, authCfgs[j].Authority.Identifier)
		}

	}

	// create a consensus and exchange signatures
	for i, s := range stateAuthority {
		s.state = stateAcceptSignature
		myCertificate, err := s.tabulate(s.votingEpoch)
		assert.NoError(err)
		for j, a := range stateAuthority {
			if j == i {
				continue
			}
			a.certificates[s.votingEpoch][s.identityPubKey()] = myCertificate
		}

	}

	// save the consensus
	for _, s := range stateAuthority {
		s.consense(s.votingEpoch)
	}

	// verify that each authority produced the same output
	docs := make([][]byte, len(stateAuthority))
	for i, s := range stateAuthority {
		d, ok := s.documents[s.votingEpoch]
		assert.True(ok)
		docs[i] = d.raw
		if i == 0 {
			continue
		}
		require.True(bytes.Equal(docs[i-1], d.raw))
	}
}

func genVotingAuthoritiesCfg(parameters *config.Parameters, numAuthorities int) ([]*config.Config, error) {
	configs := []*config.Config{}
	basePort := 30000
	lastPort := basePort + 1

	// initial generation of key material for each authority
	peersMap := make(map[[eddsa.PublicKeySize]byte]*config.AuthorityPeer)
	for i := 0; i < numAuthorities; i++ {
		cfg := new(config.Config)
		cfg.Logging = &config.Logging{Disable: false, File: "", Level: "DEBUG"}
		cfg.Parameters = parameters
		cfg.Authority = &config.Authority{
			Identifier: fmt.Sprintf("authority-%v", i),
			Addresses:  []string{fmt.Sprintf("127.0.0.1:%d", lastPort)},
		}
		lastPort += 1
		idKey, err := eddsa.NewKeypair(rand.Reader)
		if err != nil {
			return nil, err
		}
		linkKey, err := ecdh.NewKeypair(rand.Reader)
		if err != nil {
			return nil, err
		}
		cfg.Debug = &config.Debug{
			LinkKey:          linkKey,
			IdentityKey:      idKey,
			Layers:           3,
			MinNodesPerLayer: 1,
			GenerateOnly:     false,
		}
		configs = append(configs, cfg)
		authorityPeer := &config.AuthorityPeer{
			IdentityPublicKey: cfg.Debug.IdentityKey.PublicKey(),
			LinkPublicKey:     cfg.Debug.LinkKey.PublicKey(),
			Addresses:         cfg.Authority.Addresses,
		}
		peersMap[cfg.Debug.IdentityKey.PublicKey().ByteArray()] = authorityPeer
	}

	// tell each authority about it's peers
	for i := 0; i < numAuthorities; i++ {
		peers := []*config.AuthorityPeer{}
		for id, peer := range peersMap {
			if !bytes.Equal(id[:], configs[i].Debug.IdentityKey.PublicKey().Bytes()) {
				peers = append(peers, peer)
			}
		}
		configs[i].Authorities = peers
	}
	return configs, nil
}

func genProviderConfig(name string, pki *sConfig.PKI, port uint16) (*sConfig.Config, error) {
	const serverLogFile = ""

	cfg := new(sConfig.Config)

	// Server section.
	cfg.Server = new(sConfig.Server)
	cfg.Server.Identifier = name
	cfg.Server.Addresses = []string{fmt.Sprintf("127.0.0.1:%d", port)}
	cfg.Server.AltAddresses = map[string][]string{
		"TCP": []string{fmt.Sprintf("localhost:%d", port)},
	}

	cfg.Server.DataDir = "/foo/bar"
	cfg.Server.IsProvider = true

	// Debug section.
	cfg.Debug = new(sConfig.Debug)

	// Generate keys
	idKey, err := eddsa.NewKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}
	cfg.Debug.IdentityKey = idKey

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
		return nil, err
	}
	return cfg, nil

}

func genMixConfig(name string, pki *sConfig.PKI, port uint16) (*sConfig.Config, error) {
	const serverLogFile = ""

	cfg := new(sConfig.Config)

	// Server section.
	cfg.Server = new(sConfig.Server)
	cfg.Server.Identifier = name
	cfg.Server.Addresses = []string{fmt.Sprintf("127.0.0.1:%d", port)}
	cfg.Server.DataDir = "/foo/bar"
	cfg.Server.IsProvider = false

	// Debug section.
	cfg.Debug = new(sConfig.Debug)

	// Generate keys
	idKey, err := eddsa.NewKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}
	cfg.Debug.IdentityKey = idKey

	// PKI section.
	cfg.PKI = pki

	// Logging section.
	cfg.Logging = new(sConfig.Logging)
	cfg.Logging.File = serverLogFile
	cfg.Logging.Level = "DEBUG"
	err = cfg.FixupAndValidate()
	if err != nil {
		return nil, err
	}
	return cfg, nil
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
