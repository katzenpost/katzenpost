// SPDX-License-Identifier: AGPL-3.0-only

package genconfig

import (
	"testing"

	"github.com/stretchr/testify/require"

	vConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

func TestInitializeKatzenpostDescriptorMetadata(t *testing.T) {
	s := InitializeKatzenpost(&Config{ContactInfo: "ops@example.org", SoftwareVersion: "auto"})
	require.Equal(t, "ops@example.org", s.ContactInfo)
	require.Equal(t, "auto", s.SoftwareVersion)
}

func TestGenConfigDescriptorMetadata(t *testing.T) {
	for _, tc := range []struct{ contact, version string }{
		{"", ""},
		{"ops@example.org", "auto"},
		{"ops@example.org", "testnet 1.0"},
	} {
		s := testKatzenpost(t)
		s.BaseDir = t.TempDir()
		s.LastPort = 30000
		s.LogLevel = "DEBUG"
		s.ReplicaNIKEScheme = replicaCommon.NikeScheme
		s.ContactInfo = tc.contact
		s.SoftwareVersion = tc.version
		require.NoError(t, s.GenVotingAuthoritiesCfg(2, &vConfig.Parameters{Mu: 0.005, LambdaP: 0.001}, 5, s.WireKEMScheme))
		require.NoError(t, s.GenNodeConfig(false, false, true))
		require.NoError(t, s.GenNodeConfig(true, false, true))
		require.NoError(t, s.GenNodeConfig(false, true, true))
		require.NoError(t, s.GenReplicaNodeConfig())
		for _, n := range s.NodeConfigs {
			require.Equal(t, tc.contact, n.Server.ContactInfo, n.Server.Identifier)
			require.Equal(t, tc.version, n.Server.SoftwareVersion, n.Server.Identifier)
		}
		require.Equal(t, tc.contact, s.ReplicaNodeConfigs[0].ContactInfo)
		require.Equal(t, tc.version, s.ReplicaNodeConfigs[0].SoftwareVersion)
	}
}
