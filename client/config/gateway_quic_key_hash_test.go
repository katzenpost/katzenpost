// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func quicGatewayTOML(t *testing.T, quicKeyHash interface{}) map[string]interface{} {
	d := gatewayTOMLWithScheme(t, testSchemeName)
	d["Addresses"] = []interface{}{"quic://127.0.0.1:1234", "tcp://127.0.0.1:1234"}
	if quicKeyHash != nil {
		d["QUICKeyHash"] = quicKeyHash
	}
	return d
}

func TestGatewayQUICKeyHashRoundTrips(t *testing.T) {
	want := hex.EncodeToString(bytes.Repeat([]byte{0xab}, cpki.QUICKeyHashSize))
	gw := new(Gateway)
	require.NoError(t, gw.UnmarshalTOML(quicGatewayTOML(t, want)))
	var buf bytes.Buffer
	require.NoError(t, toml.NewEncoder(&buf).Encode(gw))
	require.Contains(t, buf.String(), "QUICKeyHash = \""+want+"\"", "a PinnedGateway dropped its QUICKeyHash")
}

func TestGatewayWithoutAQUICKeyHashWritesNone(t *testing.T) {
	gw := new(Gateway)
	require.NoError(t, gw.UnmarshalTOML(gatewayTOMLWithScheme(t, testSchemeName)))
	var buf bytes.Buffer
	require.NoError(t, toml.NewEncoder(&buf).Encode(gw))
	require.False(t, strings.Contains(buf.String(), "QUICKeyHash"), buf.String())
}

func TestGatewayRejectsAMalformedQUICKeyHash(t *testing.T) {
	for _, value := range []interface{}{
		"",
		"zz",
		hex.EncodeToString(make([]byte, cpki.QUICKeyHashSize-1)),
		hex.EncodeToString(make([]byte, 2*cpki.QUICKeyHashSize)),
		42,
	} {
		require.Error(t, new(Gateway).UnmarshalTOML(quicGatewayTOML(t, value)), "a PinnedGateway accepted QUICKeyHash %v", value)
	}
}

var optedInToQUIC = []string{cpki.TransportQUIC, cpki.TransportTCP}

func TestConfigRejectsAQUICPinnedGatewayWithoutAQUICKeyHash(t *testing.T) {
	cfg := loadRawConfig(t)
	cfg.PreferedTransports = optedInToQUIC
	gw := new(Gateway)
	require.NoError(t, gw.UnmarshalTOML(quicGatewayTOML(t, nil)))
	cfg.PinnedGateways.Gateways = []*Gateway{gw}
	err := cfg.FixupAndValidate()
	require.Error(t, err, "a client that opted in to quic accepted a PinnedGateway with a quic address and no QUICKeyHash")
	require.ErrorContains(t, err, "gateway1")

	cfg = loadRawConfig(t)
	cfg.PreferedTransports = optedInToQUIC
	pinned := new(Gateway)
	require.NoError(t, pinned.UnmarshalTOML(quicGatewayTOML(t, hex.EncodeToString(bytes.Repeat([]byte{1}, cpki.QUICKeyHashSize)))))
	cfg.PinnedGateways.Gateways = []*Gateway{pinned}
	require.NoError(t, cfg.FixupAndValidate())

	cfg = loadRawConfig(t)
	cfg.PreferedTransports = optedInToQUIC
	tcpOnly := new(Gateway)
	require.NoError(t, tcpOnly.UnmarshalTOML(gatewayTOMLWithScheme(t, testSchemeName)))
	cfg.PinnedGateways.Gateways = []*Gateway{tcpOnly}
	require.NoError(t, cfg.FixupAndValidate())
}

func TestConfigAcceptsAnUnpinnedQUICGatewayWhenQUICIsOff(t *testing.T) {
	for _, transports := range [][]string{nil, {cpki.TransportTCP}} {
		cfg := loadRawConfig(t)
		cfg.PreferedTransports = transports
		gw := new(Gateway)
		require.NoError(t, gw.UnmarshalTOML(quicGatewayTOML(t, nil)))
		cfg.PinnedGateways.Gateways = []*Gateway{gw}
		require.NoError(t, cfg.FixupAndValidate(), "a client without quic refused a PinnedGateway it will dial over tcp, PreferedTransports %v", transports)
	}
}
