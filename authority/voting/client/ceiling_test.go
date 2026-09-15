// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/sign"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
)

func clientCfg(signScheme sign.Scheme, kemScheme kem.Scheme, sphinx string, nAuth int) *Config {
	auths := make([]*config.Authority, nAuth)
	for i := range auths {
		auths[i] = &config.Authority{}
	}
	return &Config{
		PKISignatureScheme: signScheme,
		KEMScheme:          kemScheme,
		Geo:                &geo.Geometry{NIKEName: sphinx},
		Authorities:        auths,
	}
}

// TestClientCeilingScalesWithWireKEM proves the client derives a PKI-scaled
// ceiling from its own config: a McEliece link key yields a larger ceiling than
// an MLKEM one, with no config change. This is the fact the client can derive
// because it holds the scheme objects and the authority count.
func TestClientCeilingScalesWithWireKEM(t *testing.T) {
	signScheme := signschemes.ByName("Ed25519 Sphincs+")
	if signScheme == nil {
		t.Skip("Ed25519 Sphincs+ is not built on this platform")
	}
	small := clientCfg(signScheme, kemschemes.ByName("MLKEM768-X25519"), "x25519", 6).deriveMaxMessageSize()
	big := clientCfg(signScheme, kemschemes.ByName("mceliece348864-X25519"), "x25519", 6).deriveMaxMessageSize()
	require.Greater(t, big, small, "McEliece link keys must yield a larger client ceiling than MLKEM")
	require.GreaterOrEqual(t, small, 256*1024)
}

// TestClientCeilingFallsBackWithoutSchemes ensures a config missing schemes
// yields the built-in default rather than panicking.
func TestClientCeilingFallsBackWithoutSchemes(t *testing.T) {
	cfg := &Config{Authorities: []*config.Authority{{}}}
	require.Equal(t, wire.DefaultMaxPKIMessageSize, cfg.deriveMaxMessageSize())
}

// TestClientCeilingWithSchemesIsNotFallback proves a Config that carries the
// configured PKI schemes derives a real ceiling instead of the flat
// DefaultMaxPKIMessageSize fallback. This is the property a consumer gains once
// its schemes are wired into the Config rather than left unset.
func TestClientCeilingWithSchemesIsNotFallback(t *testing.T) {
	signScheme := signschemes.ByName("Ed25519 Sphincs+")
	if signScheme == nil {
		t.Skip("Ed25519 Sphincs+ is not built on this platform")
	}
	kemScheme := kemschemes.ByName("MLKEM768-X25519")
	require.NotNil(t, kemScheme)

	withSchemes := clientCfg(signScheme, kemScheme, "x25519", 3).deriveMaxMessageSize()
	require.NotEqual(t, wire.DefaultMaxPKIMessageSize, withSchemes,
		"a configured consumer must derive a ceiling, not fall back to the flat default")

	noSchemes := (&Config{Authorities: []*config.Authority{{}}}).deriveMaxMessageSize()
	require.Equal(t, wire.DefaultMaxPKIMessageSize, noSchemes,
		"a consumer without schemes keeps the flat default ceiling")
}
