// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
)

func TestVotingThresholdsFormula(t *testing.T) {
	for _, tc := range []struct{ n, threshold, dissenters int }{
		{1, 1, -1},
		{2, 2, 0},
		{3, 2, 0},
		{4, 3, 1},
		{5, 3, 1},
		{6, 4, 2},
		{7, 4, 2},
	} {
		th, di := votingThresholds(tc.n)
		require.Equal(t, tc.threshold, th, "n=%d threshold", tc.n)
		require.Equal(t, tc.dissenters, di, "n=%d dissenters", tc.n)
	}
}

func TestVotingThresholdsUseTheVerifierSet(t *testing.T) {
	require := require.New(t)
	for _, n := range []int{3, 4, 5} {
		peerKeys, cfgs, err := genVotingAuthoritiesCfg(&config.Parameters{}, n)
		require.NoError(err)
		for i, cfg := range cfgs {
			require.Len(cfg.Authorities, n-1)
			verifiers := make(map[[hash.HashSize]byte]sign.PublicKey)
			for _, auth := range cfg.Authorities {
				verifiers[hash.Sum256From(auth.IdentityPublicKey)] = auth.IdentityPublicKey
			}
			verifiers[hash.Sum256From(peerKeys[i].idPubKey)] = sign.PublicKey(peerKeys[i].idPubKey)
			require.Len(verifiers, n)
			th, di := votingThresholds(len(verifiers))
			require.Equal(n/2+1, th)
			require.Equal(n/2-1, di)
			if n%2 == 0 {
				require.NotEqual(len(cfg.Authorities)/2-1, di)
			}
		}
	}
}
