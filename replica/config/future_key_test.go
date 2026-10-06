// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadIgnoresUnknownFutureKeys(t *testing.T) {
	b, err := os.ReadFile("testdata/replica.toml")
	require.NoError(t, err)
	_, err = Load([]byte("FutureKey = \"x\"\n"+string(b)+"\n[FutureTable]\nFutureKey = 1\n"), false)
	require.NoError(t, err)
}
