// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"os"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/transport"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
)

// validListen returns a minimal non-empty ListenConfig suitable for
// exercising validation branches that sit downstream of the Listen check.
func validListen() *transport.ListenConfig {
	return &transport.ListenConfig{
		Tcp: &transport.TcpListenConfig{Address: "127.0.0.1:0"},
	}
}

func loadTestConfig(t *testing.T) *Config {
	t.Helper()
	cfg, err := LoadFile("../testdata/client.toml")
	require.NoError(t, err)
	return cfg
}

// loadRawConfig loads TOML without running FixupAndValidate,
// so we can test individual validation branches.
func loadRawConfig(t *testing.T) *Config {
	t.Helper()
	b, err := os.ReadFile("../testdata/client.toml")
	require.NoError(t, err)
	cfg := new(Config)
	err = toml.Unmarshal(b, cfg)
	require.NoError(t, err)
	return cfg
}

func TestLoggingValidate(t *testing.T) {
	t.Run("valid levels", func(t *testing.T) {
		for _, level := range []string{"ERROR", "WARNING", "NOTICE", "INFO", "DEBUG", "error", "warning", "notice", "info", "debug"} {
			l := &Logging{Level: level}
			err := l.validate()
			require.NoError(t, err, "level %q should be valid", level)
		}
	})

	t.Run("empty level defaults to NOTICE", func(t *testing.T) {
		l := &Logging{Level: ""}
		err := l.validate()
		require.NoError(t, err)
		require.Equal(t, defaultLogLevel, l.Level)
	})

	t.Run("invalid level", func(t *testing.T) {
		l := &Logging{Level: "TRACE"}
		err := l.validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid")
	})
}

func TestDebugFixup(t *testing.T) {
	t.Run("all zeros get defaults", func(t *testing.T) {
		d := &Debug{}
		d.fixup()
		require.Equal(t, defaultPollingInterval, d.PollingInterval)
		require.Equal(t, defaultInitialMaxPKIRetrievalDelay, d.InitialMaxPKIRetrievalDelay)
		require.Equal(t, defaultSessionDialTimeout, d.SessionDialTimeout)
	})

	t.Run("non-zero values preserved", func(t *testing.T) {
		d := &Debug{
			PollingInterval:             5,
			InitialMaxPKIRetrievalDelay: 15,
			SessionDialTimeout:          60,
		}
		d.fixup()
		require.Equal(t, 5, d.PollingInterval)
		require.Equal(t, 15, d.InitialMaxPKIRetrievalDelay)
		require.Equal(t, 60, d.SessionDialTimeout)
	})
}

func TestUpstreamProxyConfig(t *testing.T) {
	cfg := loadTestConfig(t)
	proxyConfig := cfg.UpstreamProxyConfig()
	require.NotNil(t, proxyConfig)
}

func TestFixupAndValidate(t *testing.T) {
	t.Run("empty WireKEMScheme", func(t *testing.T) {
		cfg := &Config{WireKEMScheme: ""}
		err := cfg.FixupAndValidate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "WireKEMScheme")
	})

	t.Run("invalid WireKEMScheme", func(t *testing.T) {
		cfg := &Config{WireKEMScheme: "nonexistent-kem"}
		err := cfg.FixupAndValidate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "WireKEMScheme")
	})

	t.Run("missing Listen", func(t *testing.T) {
		cfg := &Config{WireKEMScheme: "xwing"}
		err := cfg.FixupAndValidate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "transport")
	})

	t.Run("missing PinnedGateways", func(t *testing.T) {
		cfg := &Config{
			WireKEMScheme: "xwing",
			Listen:        validListen(),
		}
		err := cfg.FixupAndValidate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "PinnedGateways")
	})

	t.Run("missing SphinxGeometry", func(t *testing.T) {
		cfg := &Config{
			WireKEMScheme:  "xwing",
			Listen:         validListen(),
			PinnedGateways: &Gateways{},
		}
		err := cfg.FixupAndValidate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "SphinxGeometry")
	})

	t.Run("invalid SphinxGeometry", func(t *testing.T) {
		cfg := &Config{
			WireKEMScheme:  "xwing",
			Listen:         validListen(),
			PinnedGateways: &Gateways{},
			SphinxGeometry: &geo.Geometry{}, // empty = invalid
		}
		err := cfg.FixupAndValidate()
		require.Error(t, err)
	})

	t.Run("missing PigeonholeGeometry", func(t *testing.T) {
		raw := loadRawConfig(t)
		raw.PigeonholeGeometry = nil
		err := raw.FixupAndValidate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "PigeonholeGeometry")
	})

	t.Run("invalid PigeonholeGeometry", func(t *testing.T) {
		raw := loadRawConfig(t)
		raw.PigeonholeGeometry = &pigeonholeGeo.Geometry{} // empty = invalid
		err := raw.FixupAndValidate()
		require.Error(t, err)
	})

	t.Run("nil Logging gets default", func(t *testing.T) {
		raw := loadRawConfig(t)
		raw.Logging = nil
		err := raw.FixupAndValidate()
		require.NoError(t, err)
		require.NotNil(t, raw.Logging)
	})

	t.Run("nil Debug gets default", func(t *testing.T) {
		raw := loadRawConfig(t)
		raw.Debug = nil
		err := raw.FixupAndValidate()
		require.NoError(t, err)
		require.NotNil(t, raw.Debug)
		require.Equal(t, defaultPollingInterval, raw.Debug.PollingInterval)
		require.Equal(t, defaultInitialMaxPKIRetrievalDelay, raw.Debug.InitialMaxPKIRetrievalDelay)
	})

	t.Run("existing Debug gets fixup", func(t *testing.T) {
		raw := loadRawConfig(t)
		raw.Debug = &Debug{} // all zeros
		err := raw.FixupAndValidate()
		require.NoError(t, err)
		require.Equal(t, defaultPollingInterval, raw.Debug.PollingInterval)
	})

	t.Run("invalid logging level", func(t *testing.T) {
		raw := loadRawConfig(t)
		raw.Logging = &Logging{Level: "INVALID_LEVEL"}
		err := raw.FixupAndValidate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid")
	})

	t.Run("invalid upstream proxy", func(t *testing.T) {
		raw := loadRawConfig(t)
		raw.UpstreamProxy = &UpstreamProxy{Type: "bogus-proxy"}
		err := raw.FixupAndValidate()
		require.Error(t, err)
	})

	t.Run("valid config passes", func(t *testing.T) {
		cfg := loadTestConfig(t)
		require.NotNil(t, cfg)
	})
}

func TestLoad(t *testing.T) {
	t.Run("valid toml", func(t *testing.T) {
		b, err := os.ReadFile("../testdata/client.toml")
		require.NoError(t, err)
		cfg, err := Load(b)
		require.NoError(t, err)
		require.NotNil(t, cfg)
	})

	t.Run("invalid toml", func(t *testing.T) {
		_, err := Load([]byte("this is not valid toml {{{"))
		require.Error(t, err)
	})

	t.Run("empty toml fails validation", func(t *testing.T) {
		_, err := Load([]byte(""))
		require.Error(t, err)
	})
}

func TestLoadFile(t *testing.T) {
	t.Run("valid file", func(t *testing.T) {
		cfg, err := LoadFile("../testdata/client.toml")
		require.NoError(t, err)
		require.NotNil(t, cfg)
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := LoadFile("/nonexistent/path/config.toml")
		require.Error(t, err)
	})
}

func TestGetAddresses(t *testing.T) {
	t.Run("valid tcp", func(t *testing.T) {
		addrs, err := getAddresses([]interface{}{"tcp://127.0.0.1:30000"})
		require.NoError(t, err)
		require.Len(t, addrs, 1)
	})

	t.Run("valid tcp4", func(t *testing.T) {
		addrs, err := getAddresses([]interface{}{"tcp4://127.0.0.1:30000"})
		require.NoError(t, err)
		require.Len(t, addrs, 1)
	})

	t.Run("valid tcp6", func(t *testing.T) {
		addrs, err := getAddresses([]interface{}{"tcp6://[::1]:30000"})
		require.NoError(t, err)
		require.Len(t, addrs, 1)
	})

	t.Run("valid quic", func(t *testing.T) {
		addrs, err := getAddresses([]interface{}{"quic://127.0.0.1:30000"})
		require.NoError(t, err)
		require.Len(t, addrs, 1)
	})

	t.Run("valid onion", func(t *testing.T) {
		addrs, err := getAddresses([]interface{}{"onion://example.onion:80"})
		require.NoError(t, err)
		require.Len(t, addrs, 1)
	})

	t.Run("invalid scheme", func(t *testing.T) {
		_, err := getAddresses([]interface{}{"http://127.0.0.1:30000"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "Invalid Scheme")
	})

	t.Run("not a string", func(t *testing.T) {
		_, err := getAddresses([]interface{}{12345})
		require.Error(t, err)
		require.Contains(t, err.Error(), "not a string")
	})

	t.Run("empty list", func(t *testing.T) {
		_, err := getAddresses([]interface{}{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "No valid Addresses")
	})

	t.Run("multiple valid", func(t *testing.T) {
		addrs, err := getAddresses([]interface{}{
			"tcp://127.0.0.1:30000",
			"tcp://127.0.0.1:30001",
		})
		require.NoError(t, err)
		require.Len(t, addrs, 2)
	})

	t.Run("unparseable URL", func(t *testing.T) {
		// url.Parse rarely errors, but a bare control character will do it
		_, err := getAddresses([]interface{}{string([]byte{0x7f})})
		// Even if url.Parse doesn't error, the scheme will be empty -> "Invalid Scheme"
		require.Error(t, err)
	})
}

func TestUpstreamProxyToProxyConfig(t *testing.T) {
	t.Run("none type", func(t *testing.T) {
		p := &UpstreamProxy{Type: "none"}
		cfg, err := p.toProxyConfig()
		require.NoError(t, err)
		require.NotNil(t, cfg)
	})

	t.Run("empty type defaults to none", func(t *testing.T) {
		p := &UpstreamProxy{Type: ""}
		cfg, err := p.toProxyConfig()
		require.NoError(t, err)
		require.NotNil(t, cfg)
	})

	t.Run("invalid type", func(t *testing.T) {
		p := &UpstreamProxy{Type: "invalid-proxy-type"}
		_, err := p.toProxyConfig()
		require.Error(t, err)
	})

	t.Run("socks5 missing address", func(t *testing.T) {
		p := &UpstreamProxy{
			Type:    "socks5",
			Network: "tcp",
		}
		_, err := p.toProxyConfig()
		require.Error(t, err)
	})
}

func TestUnmarshalTOML(t *testing.T) {
	t.Run("valid gateway from test config", func(t *testing.T) {
		cfg := loadTestConfig(t)
		require.NotNil(t, cfg.PinnedGateways)
		require.NotEmpty(t, cfg.PinnedGateways.Gateways)
		gw := cfg.PinnedGateways.Gateways[0]
		require.Equal(t, "gateway1", gw.Name)
		require.NotNil(t, gw.IdentityKey)
		require.NotNil(t, gw.LinkKey)
		require.NotEmpty(t, gw.Addresses)
	})

	t.Run("empty PKISignatureScheme panics", func(t *testing.T) {
		data := map[string]interface{}{
			"Name":               "test",
			"PKISignatureScheme": "",
			"IdentityKey":        "unused",
			"WireKEMScheme":      "xwing",
			"LinkKey":            "unused",
			"Addresses":          []interface{}{"tcp://127.0.0.1:1234"},
		}
		gw := &Gateway{}
		require.Panics(t, func() {
			gw.UnmarshalTOML(data)
		})
	})

	t.Run("invalid PKISignatureScheme panics", func(t *testing.T) {
		data := map[string]interface{}{
			"Name":               "test",
			"PKISignatureScheme": "nonexistent-scheme",
			"IdentityKey":        "unused",
			"WireKEMScheme":      "xwing",
			"LinkKey":            "unused",
			"Addresses":          []interface{}{"tcp://127.0.0.1:1234"},
		}
		gw := &Gateway{}
		require.Panics(t, func() {
			gw.UnmarshalTOML(data)
		})
	})

	t.Run("bad IdentityKey PEM", func(t *testing.T) {
		data := map[string]interface{}{
			"Name":               "test",
			"PKISignatureScheme": "Ed25519",
			"IdentityKey":        "not-a-pem-string",
			"WireKEMScheme":      "xwing",
			"LinkKey":            "unused",
			"Addresses":          []interface{}{"tcp://127.0.0.1:1234"},
		}
		gw := &Gateway{}
		err := gw.UnmarshalTOML(data)
		require.Error(t, err)
	})

	t.Run("empty WireKEMScheme", func(t *testing.T) {
		// Need a valid identity key first
		cfg := loadTestConfig(t)
		gw0 := cfg.PinnedGateways.Gateways[0]
		// Re-read raw TOML to get the PEM string
		b, err := os.ReadFile("../testdata/client.toml")
		require.NoError(t, err)

		// Parse raw to get the identity key PEM
		raw := make(map[string]interface{})
		err = toml.Unmarshal(b, &raw)
		require.NoError(t, err)
		_ = gw0

		data := map[string]interface{}{
			"Name":               "test",
			"PKISignatureScheme": "Ed25519",
			"IdentityKey":        "-----BEGIN ED25519 PUBLIC KEY-----\n/JR6wXG2WDkB8+iKQMpDIzwRwcF6kTIwtbibV0OXfcE=\n-----END ED25519 PUBLIC KEY-----\n",
			"WireKEMScheme":      "",
			"LinkKey":            "unused",
			"Addresses":          []interface{}{"tcp://127.0.0.1:1234"},
		}
		gw := &Gateway{}
		err = gw.UnmarshalTOML(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "WireKEMScheme")
	})

	t.Run("invalid WireKEMScheme", func(t *testing.T) {
		data := map[string]interface{}{
			"Name":               "test",
			"PKISignatureScheme": "Ed25519",
			"IdentityKey":        "-----BEGIN ED25519 PUBLIC KEY-----\n/JR6wXG2WDkB8+iKQMpDIzwRwcF6kTIwtbibV0OXfcE=\n-----END ED25519 PUBLIC KEY-----\n",
			"WireKEMScheme":      "nonexistent-kem",
			"LinkKey":            "unused",
			"Addresses":          []interface{}{"tcp://127.0.0.1:1234"},
		}
		gw := &Gateway{}
		err := gw.UnmarshalTOML(data)
		require.Error(t, err)
		require.Contains(t, err.Error(), "WireKEMScheme")
	})

	t.Run("bad LinkKey PEM", func(t *testing.T) {
		data := map[string]interface{}{
			"Name":               "test",
			"PKISignatureScheme": "Ed25519",
			"IdentityKey":        "-----BEGIN ED25519 PUBLIC KEY-----\n/JR6wXG2WDkB8+iKQMpDIzwRwcF6kTIwtbibV0OXfcE=\n-----END ED25519 PUBLIC KEY-----\n",
			"WireKEMScheme":      "xwing",
			"LinkKey":            "not-a-pem-string",
			"Addresses":          []interface{}{"tcp://127.0.0.1:1234"},
		}
		gw := &Gateway{}
		err := gw.UnmarshalTOML(data)
		require.Error(t, err)
	})

	t.Run("Addresses not a slice", func(t *testing.T) {
		// We need valid IdentityKey and LinkKey. Read from test config TOML.
		b, err := os.ReadFile("../testdata/client.toml")
		require.NoError(t, err)
		raw := make(map[string]interface{})
		err = toml.Unmarshal(b, &raw)
		require.NoError(t, err)

		pinnedGateways := raw["PinnedGateways"].(map[string]interface{})
		gateways := pinnedGateways["Gateways"].([]map[string]interface{})
		gw0 := gateways[0]

		// Override Addresses with a non-slice
		gw0["Addresses"] = "not-a-slice"
		gw := &Gateway{}
		err = gw.UnmarshalTOML(gw0)
		require.Error(t, err)
	})

	t.Run("Addresses with invalid scheme", func(t *testing.T) {
		b, err := os.ReadFile("../testdata/client.toml")
		require.NoError(t, err)
		raw := make(map[string]interface{})
		err = toml.Unmarshal(b, &raw)
		require.NoError(t, err)

		pinnedGateways := raw["PinnedGateways"].(map[string]interface{})
		gateways := pinnedGateways["Gateways"].([]map[string]interface{})
		gw0 := gateways[0]

		gw0["Addresses"] = []interface{}{"http://invalid:1234"}
		gw := &Gateway{}
		err = gw.UnmarshalTOML(gw0)
		require.Error(t, err)
	})
}
