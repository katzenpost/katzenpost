// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveSoftwareVersion(t *testing.T) {
	const build = "v0.0.99 rev 9317791fcdf7c5b9edf1a75aea0df419396c4fec"
	require.Equal(t, "", ResolveSoftwareVersion("", build))
	require.Equal(t, "custom 1.0", ResolveSoftwareVersion("custom 1.0", build))
	require.Equal(t, build, ResolveSoftwareVersion(AutoSoftwareVersion, build))
	require.Equal(t, "(devel)", ResolveSoftwareVersion(AutoSoftwareVersion, "(devel)"))
}

func TestResolveSoftwareVersionBounded(t *testing.T) {
	build := "v1.2.3\x00\xff rev " + strings.Repeat("ab\x7f\n", 64)
	got := ResolveSoftwareVersion(AutoSoftwareVersion, build)
	require.NoError(t, IsSoftwareVersionWellFormed(got))
	require.Len(t, got, maxSoftwareVersionLength)
	require.Equal(t, "v1.2.3?? rev ab??ab??", got[:21])
	require.Equal(t, got, ResolveSoftwareVersion(AutoSoftwareVersion, build))
}
