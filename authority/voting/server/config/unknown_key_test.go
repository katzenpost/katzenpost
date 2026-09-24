// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"
)

func TestRemovedServerKeysAreIgnored(t *testing.T) {
	cfg := new(Config)
	err := toml.Unmarshal([]byte("[Server]\nIdentifier = \"a\"\nCloseDelaySec = 3\n"), cfg)
	require.NoError(t, err)
	require.Equal(t, "a", cfg.Server.Identifier)
}
