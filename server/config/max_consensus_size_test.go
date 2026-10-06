// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
)

func TestVotingRejectsNegativeMaxConsensusSize(t *testing.T) {
	v := &Voting{}
	_, err := toml.Decode("MaxConsensusSize = -1\n", v)
	require.NoError(t, err)
	v.Authorities = []*config.Authority{}
	require.Error(t, v.validate(""))
}
