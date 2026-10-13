// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDescriptorMetadataFlags(t *testing.T) {
	for _, name := range []string{"contactInfo", "softwareVersion"} {
		cmd := newRootCommand()
		v, err := cmd.Flags().GetString(name)
		require.NoError(t, err, name)
		require.Empty(t, v, name)

		cmd = newRootCommand()
		require.NoError(t, cmd.ParseFlags([]string{"--" + name, "x y"}), name)
		v, err = cmd.Flags().GetString(name)
		require.NoError(t, err, name)
		require.Equal(t, "x y", v, name)
	}
}
