// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
)

func TestFetchChoosesTheEpochPeriodFirst(t *testing.T) {
	t.Setenv(epochtime.EnvironmentVariable, "90s")
	err := runFetch(Config{ConfigFile: filepath.Join(t.TempDir(), "missing.toml")})
	require.ErrorContains(t, err, epochtime.EnvironmentVariable)
}
