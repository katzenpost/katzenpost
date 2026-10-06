// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/server/config"
)

func TestPKIClientConfigUsesConfiguredMaxConsensusSize(t *testing.T) {
	const size = 3 * 1024 * 1024
	cfg := &config.Config{}
	_, err := toml.Decode("[PKI]\n[PKI.Voting]\nMaxConsensusSize = 3145728\n", cfg)
	require.NoError(t, err)
	cfg.Server = &config.Server{}
	cfg.Debug = &config.Debug{}
	c := pkiClientConfig(&clientConfigGlue{cfg: cfg}, kemschemes.ByName("Xwing"), signschemes.ByName(testSchemeName))
	require.Equal(t, size, c.MaxConsensusSize)
}
