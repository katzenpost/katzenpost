// SPDX-License-Identifier: AGPL-3.0-only

package genconfig

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	vConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
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
	s.PkiSignatureScheme = signSchemes.ByName(testSchemeName)
	s.BaseDir = t.TempDir()
	s.LastPort = 30000
	s.LogLevel = "DEBUG"
	s.Transport = transport
	parameters := &vConfig.Parameters{Mu: 0.005, LambdaP: 0.001}
	require.NoError(t, s.GenVotingAuthoritiesCfg(2, parameters, 5, s.WireKEMScheme))
	for i := 0; i < 2; i++ {
		require.NoError(t, s.GenNodeConfig(true, false, true))
	}
	for i := 0; i < 4; i++ {
		require.NoError(t, s.GenNodeConfig(false, false, true))
	}
	return s
}

func addressSchemes(t *testing.T, addrs []string) string {
	t.Helper()
	var schemes []string
	for _, a := range addrs {
		schemes = append(schemes, schemeOf(t, a))
	}
	return strings.Join(schemes, "+")
}

func TestGenConfigTransport(t *testing.T) {
	tcp := []string{"tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp"}
	for transport, want := range map[string][]string{
		"":          tcp,
		"tcp":       tcp,
		"quic":      {"quic", "quic", "quic", "quic", "quic", "quic", "quic", "quic"},
		"alternate": {"tcp", "quic+tcp", "tcp", "quic+tcp", "tcp", "quic", "tcp", "quic"},
	} {
		s := transportFixture(t, transport)
		var got []string
		for _, a := range s.VotingAuthConfigs {
			got = append(got, addressSchemes(t, a.Server.Addresses))
		}
		for _, n := range s.NodeConfigs {
			require.Equal(t, n.Server.Addresses, n.Server.BindAddresses)
			got = append(got, addressSchemes(t, n.Server.Addresses))
		}
		require.Equal(t, want, got, "transport %q", transport)
	}
}

func TestGenConfigPublishesQUICKeyHashesOnlyWhenEveryAuthorityIsCurrent(t *testing.T) {
	for _, tc := range []struct {
		versions map[string]string
		publish  bool
	}{
		{nil, true},
		{map[string]string{"auth1": CurrentVersion, "mix1": "v0.0.104"}, true},
		{map[string]string{"auth2": "v0.0.104"}, false},
	} {
		s := testKatzenpost(t)
		s.PkiSignatureScheme = signSchemes.ByName(testSchemeName)
		s.BaseDir = t.TempDir()
		s.LastPort = 30000
		s.LogLevel = "DEBUG"
		s.Transport = "quic"
		s.NodeVersions = tc.versions
		s.ReplicaNIKEScheme = replicaCommon.NikeScheme
		require.NoError(t, s.GenVotingAuthoritiesCfg(2, &vConfig.Parameters{Mu: 0.005, LambdaP: 0.001}, 5, s.WireKEMScheme))
		require.NoError(t, s.GenNodeConfig(true, false, true))
		require.NoError(t, s.GenNodeConfig(false, false, true))
		require.NoError(t, s.GenReplicaNodeConfig())
		for _, a := range s.VotingAuthConfigs {
			require.Equal(t, tc.publish, a.Server.PublishQUICKeyHashes, "%v %s", tc.versions, a.Server.Identifier)
		}
	}
}

func TestGenConfigEveryAuthorityPublishesQUICKeyHashesOnAQUICNetwork(t *testing.T) {
	for transport, publish := range map[string]bool{"tcp": false, "quic": true, "alternate": true} {
		s := transportFixture(t, transport)
		for _, a := range s.VotingAuthConfigs {
			require.Equal(t, publish, a.Server.PublishQUICKeyHashes, "transport %s: %s with addresses %v", transport, a.Server.Identifier, a.Server.Addresses)
		}
	}
}
