// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
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
