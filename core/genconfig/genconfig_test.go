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

	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
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
	pigeonGeo, err := pigeonholeGeo.NewGeometryFromSphinx(sphinxGeo, nikeScheme)
	require.NoError(t, err)

	return &Katzenpost{
		OutDir:             t.TempDir(),
		LogWriter:          io.Discard,
		WireKEMScheme:      "xwing",
		PkiSignatureScheme: pkiScheme,
		SphinxGeometry:     sphinxGeo,
		PigeonholeGeometry: pigeonGeo,
	}
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
