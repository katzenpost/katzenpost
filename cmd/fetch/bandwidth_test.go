// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBandwidthFlag(t *testing.T) {
	cmd := newRootCommand()
	require.NoError(t, cmd.ParseFlags([]string{"--bandwidth"}))
	v, err := cmd.Flags().GetBool("bandwidth")
	require.NoError(t, err)
	require.True(t, v)
}
