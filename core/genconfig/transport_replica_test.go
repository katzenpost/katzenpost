// SPDX-License-Identifier: AGPL-3.0-only

package genconfig

import (
	"testing"

	"github.com/stretchr/testify/require"

	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

func TestGenReplicaNodeConfigTransport(t *testing.T) {
	for _, tc := range []struct {
		transport string
		want      []string
	}{
		{"", []string{"tcp", "tcp"}},
		{"tcp", []string{"tcp", "tcp"}},
		{"quic", []string{"quic", "quic"}},
		{"alternate", []string{"tcp", "quic"}},
	} {
		t.Run(tc.transport, func(t *testing.T) {
			s := testKatzenpost(t)
			s.BaseDir = t.TempDir()
			s.LastPort = 30000
			s.Transport = tc.transport
			s.ReplicaNIKEScheme = replicaCommon.NikeScheme
			var got []string
			for i := 0; i < 2; i++ {
				require.NoError(t, s.GenReplicaNodeConfig())
				r := s.ReplicaNodeConfigs[i]
				require.Len(t, r.Addresses, 1)
				got = append(got, schemeOf(t, r.Addresses[0]))
			}
			require.Equal(t, tc.want, got)
		})
	}
}
