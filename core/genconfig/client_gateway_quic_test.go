// SPDX-License-Identifier: AGPL-3.0-only

package genconfig

import (
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	cConfig "github.com/katzenpost/katzenpost/client/config"
	quicCommon "github.com/katzenpost/katzenpost/quic/common"
)

type writtenGateway struct {
	Name        string
	Addresses   []string
	QUICKeyHash string
}

type writtenClient struct {
	PreferedTransports []string
	PinnedGateways     struct{ Gateways []writtenGateway }
}

func writtenClientConfig(t *testing.T, transport string) (*Katzenpost, *writtenClient) {
	t.Helper()
	s := transportFixture(t, transport)
	return s, writeClientConfig(t, s)
}

func writeClientConfig(t *testing.T, s *Katzenpost) *writtenClient {
	t.Helper()
	s.DebugConfig = &cConfig.Debug{}
	require.NoError(t, s.GenClient2Cfg("tcp", "127.0.0.1:64331"))
	var c writtenClient
	_, err := toml.DecodeFile(filepath.Join(s.OutDir, "client", "client.toml"), &c)
	require.NoError(t, err)
	require.NotEmpty(t, c.PinnedGateways.Gateways)
	return &c
}

func TestGenConfigPinsEveryQUICGatewayInClientTOML(t *testing.T) {
	for _, transport := range []string{"tcp", "quic", "alternate"} {
		s, c := writtenClientConfig(t, transport)
		for _, gw := range c.PinnedGateways.Gateways {
			if !strings.Contains(strings.Join(gw.Addresses, " "), "quic://") {
				require.Empty(t, gw.QUICKeyHash, "transport %s: %s is pinned without a quic address", transport, gw.Name)
				continue
			}
			require.NotEmpty(t, gw.QUICKeyHash, "transport %s: client.toml does not pin %s's QUIC key", transport, gw.Name)
			key, err := quicCommon.ReadStaticKey(filepath.Join(s.OutDir, gw.Name, QUICKeyFile), nil)
			require.NoError(t, err)
			require.Equal(t, hex.EncodeToString(key.Hash()), gw.QUICKeyHash, "transport %s: %s", transport, gw.Name)
			require.Contains(t, gw.Addresses, "tcp://"+strings.TrimPrefix(gw.Addresses[0], "quic://"), "transport %s: %s has no tcp address for a client whose UDP fails", transport, gw.Name)
		}
	}
}

func TestGenConfigOptsTheClientInToQUICOnlyOnAQUICNetwork(t *testing.T) {
	for transport, want := range map[string][]string{
		"tcp":       nil,
		"alternate": nil,
		"quic":      {"quic", "tcp"},
	} {
		_, c := writtenClientConfig(t, transport)
		require.Equal(t, want, c.PreferedTransports, "transport %s", transport)
	}
}

func TestGenConfigLeavesAnOldGatewayToTCPInClientTOML(t *testing.T) {
	s := transportFixture(t, "quic")
	s.NodeVersions = map[string]string{"gateway1": "v0.0.104"}
	c := writeClientConfig(t, s)
	for _, gw := range c.PinnedGateways.Gateways {
		if gw.Name != "gateway1" {
			require.NotEmpty(t, gw.QUICKeyHash, gw.Name)
			continue
		}
		require.Empty(t, gw.QUICKeyHash, "an old gateway was pinned to a QUIC key it never had")
		require.Equal(t, "tcp", addressSchemes(t, gw.Addresses), "client.toml lists an old gateway's quic address it cannot pin")
	}
}
