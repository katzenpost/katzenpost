// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCoverFlag(t *testing.T) {
	cmd := newRootCommand()
	v, err := cmd.Flags().GetBool("cover")
	require.NoError(t, err)
	require.False(t, v)

	cmd = newRootCommand()
	require.NoError(t, cmd.ParseFlags([]string{"--cover"}))
	v, err = cmd.Flags().GetBool("cover")
	require.NoError(t, err)
	require.True(t, v)
}
