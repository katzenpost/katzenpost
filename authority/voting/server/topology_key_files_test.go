// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/pki"
)

func TestReloadRefusesMissingTopologyKeyFile(t *testing.T) {
	srv, cfg, path, logFile := reloadFileFixture(t)
	st := srv.state
	a := newReloadNode(t, cfg.Server.DataDir, "mixa")
	b := newReloadNode(t, cfg.Server.DataDir, "mixb")

	cfg.Mixes = []*config.Node{a.mix()}
	cfg.Topology = &config.Topology{Layers: []config.Layer{{Nodes: []config.Node{*a.mix()}}}}
	writeReloadConfig(t, path, cfg)
	require.NoError(t, srv.ReloadNodesFromFile(path))

	cfg.Mixes = []*config.Node{b.mix()}
	cfg.Topology = &config.Topology{Layers: []config.Layer{{Nodes: []config.Node{*b.mix(), {Identifier: "ghost", IdentityPublicKeyPem: "ghost-topology.pem"}}}}}
	writeReloadConfig(t, path, cfg)
	require.Error(t, srv.ReloadNodesFromFile(path))
	require.NoError(t, st.descriptorAuthorizationError(a.desc(t)))
	require.Error(t, st.descriptorAuthorizationError(b.desc(t)))

	out, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.Contains(t, string(out), "ghost-topology.pem")
}

func TestFixedTopologyReadsNoKeyFileAtVoteTime(t *testing.T) {
	f := newNodeKeyFixture(t, signSchemes.ByName(testSchemeName), "mix0", "mix1", "mix2")
	node := func(n string) *config.Node {
		return &config.Node{Identifier: n, IdentityPublicKeyFile: f.paths[n]}
	}
	cfg := &config.Config{
		Server: &config.Server{DataDir: f.dataDir, PKISignatureScheme: testSchemeName},
		Mixes:  []*config.Node{node("mix0"), node("mix1"), node("mix2")},
		Topology: &config.Topology{Layers: []config.Layer{
			{Nodes: []config.Node{*node("mix0"), *node("mix2")}},
			{Nodes: []config.Node{*node("mix1")}},
		}},
	}
	st := newStateForNodeKeys(t, cfg)
	for _, n := range []string{"mix1", "mix2"} {
		p := f.paths[n]
		if !filepath.IsAbs(p) {
			p = filepath.Join(f.dataDir, p)
		}
		require.NoError(t, os.Remove(p))
	}

	descs := make([]*pki.MixDescriptor, 0, 3)
	for _, n := range []string{"mix0", "mix1", "mix2"} {
		raw, err := f.keys[n].MarshalBinary()
		require.NoError(t, err)
		descs = append(descs, &pki.MixDescriptor{Name: n, IdentityKey: raw})
	}
	var topo [][]*pki.MixDescriptor
	require.NotPanics(t, func() { topo = st.generateFixedTopology(descs, nil) })
	require.Len(t, topo, 2)
	require.Len(t, topo[0], 2)
	require.Equal(t, "mix0", topo[0][0].Name)
	require.Equal(t, "mix2", topo[0][1].Name)
	require.Len(t, topo[1], 1)
	require.Equal(t, "mix1", topo[1][0].Name)
}
