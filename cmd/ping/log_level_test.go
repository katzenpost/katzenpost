// SPDX-FileCopyrightText: Copyright (C) 2026 Jacob Appelbaum
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLogLevelDefaultsToInfo(t *testing.T) {
	level, err := newRootCommand().Flags().GetString("log-level")
	require.NoError(t, err)
	require.Equal(t, "INFO", level, "ping logs replies as hex at DEBUG, so it must not default to it")
}
