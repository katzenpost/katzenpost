// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTransportFlag(t *testing.T) {
	cmd := newRootCommand()
	v, err := cmd.Flags().GetString("transport")
	require.NoError(t, err)
	require.Equal(t, "tcp", v)

	cmd = newRootCommand()
	require.NoError(t, cmd.ParseFlags([]string{"--transport", "alternate"}))
	v, err = cmd.Flags().GetString("transport")
	require.NoError(t, err)
	require.Equal(t, "alternate", v)
}
