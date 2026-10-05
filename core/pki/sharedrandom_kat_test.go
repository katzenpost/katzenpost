// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSharedRandomVerifyKAT(t *testing.T) {
	reveal, err := hex.DecodeString("00000000000004d2cb2f5160fc1f7e05a55ef49d340b48da2e5a78099d53393351cd579dd42503d6")
	require.NoError(t, err)
	commit, err := hex.DecodeString("00000000000004d2b9b7640f731048181a8be55e9adc396dc43b16e0274be38f6560a24b81f6f357")
	require.NoError(t, err)

	s := new(SharedRandom)
	s.SetCommit(commit)
	require.True(t, s.Verify(reveal))

	reveal[39] ^= 1
	require.False(t, s.Verify(reveal))
}

func TestSharedRandomCommitRevealRoundTrip(t *testing.T) {
	s := new(SharedRandom)
	commit, err := s.Commit(1234)
	require.NoError(t, err)

	v := new(SharedRandom)
	v.SetCommit(commit)
	require.True(t, v.Verify(s.Reveal()))
}
