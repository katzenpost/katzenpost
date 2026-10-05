// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/sign"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
)

type nodeKeyFixture struct {
	dataDir string
	keys    map[string]sign.PublicKey
	paths   map[string]string
}

func newNodeKeyFixture(t *testing.T, scheme sign.Scheme, names ...string) *nodeKeyFixture {
	f := &nodeKeyFixture{
		dataDir: t.TempDir(),
		keys:    make(map[string]sign.PublicKey),
		paths:   make(map[string]string),
	}
	elsewhere := t.TempDir()
	for i, name := range names {
		pub, _, err := scheme.GenerateKey()
		require.NoError(t, err)
		rel := name + ".public.pem"
		abs := filepath.Join(f.dataDir, rel)
		f.paths[name] = rel
		if i%2 == 1 {
			abs = filepath.Join(elsewhere, rel)
			f.paths[name] = abs
		}
		require.NoError(t, signpem.PublicKeyToFile(abs, pub))
		f.keys[name] = pub
	}
	return f
}

func newStateForNodeKeys(t *testing.T, cfg *config.Config) *state {
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	ownPub, _, err := signSchemes.ByName(cfg.Server.PKISignatureScheme).GenerateKey()
	require.NoError(t, err)
	st, err := newState(&Server{cfg: cfg, logBackend: logBackend, identityPublicKey: ownPub})
	require.NoError(t, err)
	t.Cleanup(func() { st.db.Close() })
	return st
}

func TestNewStateLoadsNodeIdentityKeys(t *testing.T) {
	for _, name := range []string{"Ed25519", "Ed25519 Sphincs+"} {
		t.Run(name, func(t *testing.T) {
			scheme := signSchemes.ByName(name)
			require.NotNil(t, scheme)
			f := newNodeKeyFixture(t, scheme, "mix0", "mix1", "gw0", "gw1", "svc0", "svc1", "rep0", "rep1")
			node := func(n string) *config.Node {
				return &config.Node{Identifier: n, IdentityPublicKeyPem: f.paths[n]}
			}
			replica := func(n string, id uint8) *config.StorageReplicaNode {
				return &config.StorageReplicaNode{Identifier: n, IdentityPublicKeyPem: f.paths[n], ReplicaID: id}
			}
			cfg := &config.Config{
				Server:          &config.Server{DataDir: f.dataDir, PKISignatureScheme: name},
				Mixes:           []*config.Node{node("mix0"), node("mix1")},
				GatewayNodes:    []*config.Node{node("gw0"), node("gw1")},
				ServiceNodes:    []*config.Node{node("svc0"), node("svc1")},
				StorageReplicas: []*config.StorageReplicaNode{replica("rep0", 0), replica("rep1", 1)},
				Topology: &config.Topology{Layers: []config.Layer{
					{Nodes: []config.Node{*node("mix0")}},
					{Nodes: []config.Node{*node("mix1")}},
				}},
			}
			st := newStateForNodeKeys(t, cfg)

			id := func(n string) [hash.HashSize]byte { return hash.Sum256From(f.keys[n]) }
			require.Equal(t, "mix0", st.authorizedMixes[id("mix0")])
			require.Equal(t, "mix1", st.authorizedMixes[id("mix1")])
			require.Equal(t, "gw0", st.authorizedGatewayNodes[id("gw0")])
			require.Equal(t, "gw1", st.authorizedGatewayNodes[id("gw1")])
			require.Equal(t, "svc0", st.authorizedServiceNodes[id("svc0")])
			require.Equal(t, "svc1", st.authorizedServiceNodes[id("svc1")])
			require.Equal(t, uint8(1), st.authorizedReplicaNodes[id("rep1")].ReplicaID)
			require.Equal(t, "rep0", st.authorizedReplicaNodes[id("rep0")].Identifier)
			for n, k := range f.keys {
				require.True(t, st.reverseHash[id(n)].Equal(k), n)
			}

			descs := make([]*pki.MixDescriptor, 0, 2)
			for _, n := range []string{"mix0", "mix1"} {
				raw, err := f.keys[n].MarshalBinary()
				require.NoError(t, err)
				descs = append(descs, &pki.MixDescriptor{Name: n, IdentityKey: raw})
			}
			topo := st.generateFixedTopology(descs, nil)
			require.Len(t, topo, 2)
			require.Equal(t, "mix0", topo[0][0].Name)
			require.Equal(t, "mix1", topo[1][0].Name)
		})
	}
}
