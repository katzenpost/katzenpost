// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/pki"
)

func TestVotingRejectsNegativeMaxConsensusSize(t *testing.T) {
	v := &Voting{}
	_, err := toml.Decode("MaxConsensusSize = -1\n", v)
	require.NoError(t, err)
	v.Authorities = []*config.Authority{}
	require.Error(t, v.validate(""))
}

func TestVotingRejectsMaxConsensusSizeAboveTheCeiling(t *testing.T) {
	v := &Voting{Authorities: []*config.Authority{}, MaxConsensusSize: pki.MaxConsensusCeiling}
	require.NoError(t, v.validate(""))
	v.MaxConsensusSize = pki.MaxConsensusCeiling + 1
	require.Error(t, v.validate(""))
}
