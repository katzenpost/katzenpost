// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadHash(t *testing.T) {
	b := []byte(newFixture(t).tomlText())
	cfg, err := Load(b, false)
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256(b), cfg.Hash())
}
