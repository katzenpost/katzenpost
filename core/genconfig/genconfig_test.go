// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package genconfig

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/schemes"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	vConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

// testKatzenpost returns a minimally populated *Katzenpost suitable for
// exercising GenClient2ThinCfg in isolation. GenClient2Cfg requires a
// full mixnet fixture (gateways, voting authorities, …); that emitter
// is validated via the docker-mixnet integration tests rather than
// here.
func testKatzenpost(t *testing.T) *Katzenpost {
	t.Helper()
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)
	pkiScheme := signSchemes.ByName("Ed25519")
	require.NotNil(t, pkiScheme)

	sphinxGeo := geo.GeometryFromUserForwardPayloadLength(nikeScheme, 2000, false, 5)

	return &Katzenpost{
		OutDir:             t.TempDir(),
		LogWriter:          io.Discard,
		WireKEMScheme:      "xwing",
		PkiSignatureScheme: pkiScheme,
		SphinxGeometry:     sphinxGeo,
	}
}

// TestKatzenpostDerivedPublishedPorts asserts the published host-port
// band follows base_port. GenerateClientConfigurations and
// GenDockerCompose derive the thin-client dial address, the kpclientd
// metrics listener port, and the prometheus scrape target from
// base_port, so parallel networks with distinct base_port values never
// collide on the host and the daemon's listener always matches the
// scrape target.
func TestKatzenpostDerivedPublishedPorts(t *testing.T) {
	s := testKatzenpost(t)
	s.BasePort = 30000

	require.Equal(t, "localhost:32000", s.thinClientDialAddress())
	require.Equal(t, uint16(32004), s.kpclientdMetricsPort())

	s.BasePort = 42000
	require.Equal(t, "localhost:44000", s.thinClientDialAddress())
	require.Equal(t, uint16(44004), s.kpclientdMetricsPort())
}

// TestDockerNetworkName asserts the bridge network name the compose file
// declares is the net directory joined to the network identifier, verbatim.
// docker/Makefile's wait, run-parallel-load and run-cp-bench attach an
// ad-hoc container to a running testnet by that exact string, so it must
// not be run through compose's project-name normalization: a distro such
// as ubuntu-26.04 keeps its dot, which is legal in a network name.
func TestDockerNetworkName(t *testing.T) {
	s := testKatzenpost(t)

	s.BaseDir = "/mixnet-alpine"
	require.Equal(t, "mixnet-alpine_katzenpost-net", s.DockerNetworkName())

	s.BaseDir = "/mixnet-ubuntu-26.04"
	require.Equal(t, "mixnet-ubuntu-26.04_katzenpost-net", s.DockerNetworkName())
}

// TestGenClient2ThinCfgEmitsDialSubtable asserts that GenClient2ThinCfg
// writes the V1 [Dial.Tcp] subtable to the thin-client config file,
// and that the resulting TOML round-trips into a thin.Config whose
// Dial.Tcp.Address matches the requested value. The flat Network /
// Address top-level fields must not be emitted.
func TestGenClient2ThinCfgEmitsDialSubtable(t *testing.T) {
	s := testKatzenpost(t)

	err := s.GenClient2ThinCfg("tcp", "localhost:64331")
	require.NoError(t, err)

	path := filepath.Join(s.OutDir, "client", "thinclient.toml")
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	text := string(content)

	require.Contains(t, text, "[Dial.Tcp]",
		"thinclient.toml must advertise the [Dial.Tcp] subtable")
	require.Contains(t, text, `Address = "localhost:64331"`,
		"Address must round-trip into the Dial subtable")

	// Old format must be absent. The check matches a newline-anchored
	// flat field to avoid false positives on Address under [Dial.Tcp].
	require.NotRegexp(t, `(?m)^Network = `, text,
		"flat top-level Network field must not be emitted")
	require.NotRegexp(t, `(?m)^Address = `, text,
		"flat top-level Address field must not be emitted (Address lives inside Dial.Tcp)")

	// Round-trip into thin.Config and assert Dial dispatches correctly.
	cfg := new(thin.Config)
	_, err = toml.Decode(text, cfg)
	require.NoError(t, err)
	require.NotNil(t, cfg.Dial, "Dial must be populated")
	require.NotNil(t, cfg.Dial.Tcp, "Dial.Tcp must be populated for a tcp config")
	require.Equal(t, "localhost:64331", cfg.Dial.Tcp.Address)
	require.NoError(t, cfg.Dial.Validate())
}

// TestGenNodeConfigPersistMixKeysOnShutdownDir asserts that a configured
// PersistMixKeysOnShutdownDir enables mix key persistence and resolves the
// directory under each node's DataDir, while leaving the field empty keeps
// persistence off (there must be no hardcoded enable).
func TestGenNodeConfigPersistMixKeysOnShutdownDir(t *testing.T) {
	newFixture := func(t *testing.T) *Katzenpost {
		t.Helper()
		s := testKatzenpost(t)
		s.BaseDir = t.TempDir()
		s.LastPort = 30000
		s.LogLevel = "DEBUG"
		parameters := &vConfig.Parameters{Mu: 0.005, LambdaP: 0.001}
		require.NoError(t, s.GenVotingAuthoritiesCfg(1, parameters, 5, s.WireKEMScheme))
		return s
	}

	t.Run("enabled", func(t *testing.T) {
		require := require.New(t)
		s := newFixture(t)
		s.PersistMixKeysOnShutdownDir = "mixkeys"

		require.NoError(s.GenNodeConfig(false, false, true))

		require.Len(s.NodeConfigs, 1)
		cfg := s.NodeConfigs[0]
		require.True(cfg.Server.PersistMixKeysOnShutdown,
			"persistence must be enabled when PersistMixKeysOnShutdownDir is set")
		require.Equal(filepath.Join(s.BaseDir, cfg.Server.Identifier, "mixkeys"),
			cfg.Server.PersistMixKeysOnShutdownDir)
	})

	t.Run("disabled by default", func(t *testing.T) {
		require := require.New(t)
		s := newFixture(t)

		require.NoError(s.GenNodeConfig(false, false, true))

		require.Len(s.NodeConfigs, 1)
		require.False(s.NodeConfigs[0].Server.PersistMixKeysOnShutdown,
			"persistence must default to off")
	})
}
