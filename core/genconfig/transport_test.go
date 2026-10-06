// SPDX-License-Identifier: AGPL-3.0-only

package genconfig

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	vConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
)

func TestValidateConfigTransport(t *testing.T) {
	for _, tr := range []string{"", "tcp", "quic", "alternate"} {
		cfg := &Config{Wirekem: "xwing", Nike: "x25519", Transport: tr}
		require.NoError(t, ValidateConfig(cfg), tr)
	}
	cfg := &Config{Wirekem: "xwing", Nike: "x25519", Transport: "udp"}
	require.Error(t, ValidateConfig(cfg))
}

func TestInitializeKatzenpostTransport(t *testing.T) {
	s := InitializeKatzenpost(&Config{Transport: "alternate"})
	require.Equal(t, "alternate", s.Transport)
}

func schemeOf(t *testing.T, addr string) string {
	t.Helper()
	u, err := url.Parse(addr)
	require.NoError(t, err)
	return u.Scheme
}

func transportFixture(t *testing.T, transport string) *Katzenpost {
	t.Helper()
	s := testKatzenpost(t)
	s.BaseDir = t.TempDir()
	s.LastPort = 30000
	s.LogLevel = "DEBUG"
	s.Transport = transport
	parameters := &vConfig.Parameters{Mu: 0.005, LambdaP: 0.001}
	require.NoError(t, s.GenVotingAuthoritiesCfg(2, parameters, 5, s.WireKEMScheme))
	for i := 0; i < 4; i++ {
		require.NoError(t, s.GenNodeConfig(false, false, true))
	}
	return s
}

func TestGenConfigTransport(t *testing.T) {
	collect := func(t *testing.T, s *Katzenpost) []string {
		var schemes []string
		for _, a := range s.VotingAuthConfigs {
			require.Len(t, a.Server.Addresses, 1)
			schemes = append(schemes, schemeOf(t, a.Server.Addresses[0]))
		}
		for _, n := range s.NodeConfigs {
			require.Len(t, n.Server.Addresses, 1)
			require.Len(t, n.Server.BindAddresses, 1)
			adv := schemeOf(t, n.Server.Addresses[0])
			require.Equal(t, adv, schemeOf(t, n.Server.BindAddresses[0]))
			schemes = append(schemes, adv)
		}
		return schemes
	}

	t.Run("default is tcp", func(t *testing.T) {
		for _, sc := range collect(t, transportFixture(t, "")) {
			require.Equal(t, "tcp", sc)
		}
	})
	t.Run("tcp", func(t *testing.T) {
		for _, sc := range collect(t, transportFixture(t, "tcp")) {
			require.Equal(t, "tcp", sc)
		}
	})
	t.Run("quic", func(t *testing.T) {
		for _, sc := range collect(t, transportFixture(t, "quic")) {
			require.Equal(t, "quic", sc)
		}
	})
	t.Run("alternate", func(t *testing.T) {
		schemes := collect(t, transportFixture(t, "alternate"))
		require.Len(t, schemes, 6)
		for i, sc := range schemes {
			want := "tcp"
			if i%2 == 1 {
				want = "quic"
			}
			require.Equal(t, want, sc, "address %d", i)
		}
	})
}
