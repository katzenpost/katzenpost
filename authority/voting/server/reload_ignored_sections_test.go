// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
)

func TestReloadLogsIgnoredSections(t *testing.T) {
	srv, cfg, path, logFile := reloadFileFixture(t)
	a := newReloadNode(t, cfg.Server.DataDir, "mixa")
	cfg.Mixes = []*config.Node{a.mix()}
	writeReloadConfig(t, path, cfg)
	running, err := config.LoadFile(path, false)
	require.NoError(t, err)
	srv.cfg = running

	require.NoError(t, srv.ReloadNodesFromFile(path))
	out, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.NotContains(t, string(out), "ignored")

	changed := *cfg
	changed.Parameters = &config.Parameters{Mu: 0.5}
	changed.Topology = &config.Topology{Layers: []config.Layer{{Nodes: []config.Node{*a.mix()}}}}
	writeReloadConfig(t, path, &changed)
	require.NoError(t, srv.ReloadNodesFromFile(path))
	out, err = os.ReadFile(logFile)
	require.NoError(t, err)
	line := regexp.MustCompile(`WARN.*ignored.*`).Find(out)
	require.NotNil(t, line)
	require.Contains(t, string(line), "Parameters")
	require.Contains(t, string(line), "Topology")
	require.NotContains(t, string(line), "Server")
	require.NotContains(t, string(line), "Authorities")
}
