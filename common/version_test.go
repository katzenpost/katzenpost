// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormatVersion(t *testing.T) {
	t.Parallel()

	rev := "49d39e958e6e8ba981c40f37479d50ef224ebdcd"
	require.Equal(t, "v0.0.92 rev "+rev, formatVersion("v0.0.92+dirty", rev))
	require.Equal(t, "v0.0.92 rev "+rev, formatVersion("v0.0.92", rev))
	require.Equal(t, "(devel)", formatVersion("(devel)", "unknown"))
	require.Equal(t, "unknown", formatVersion("unknown", ""))
}

func TestResolveVersion(t *testing.T) {
	t.Parallel()

	rev := "49d39e958e6e8ba981c40f37479d50ef224ebdcd"
	require.Equal(t, "v0.0.105-91-gb67bf6c5f-dirty", resolveVersion("v0.0.105-91-gb67bf6c5f-dirty", "(devel)", "unknown"))
	require.Equal(t, "v0.0.105-91-gb67bf6c5f", resolveVersion("v0.0.105-91-gb67bf6c5f", "v0.0.92", rev))
	require.Equal(t, "v0.0.92 rev "+rev, resolveVersion("", "v0.0.92+dirty", rev))
	require.Equal(t, "(devel) rev "+rev, resolveVersion("", "(devel)", rev))
	require.Equal(t, "unknown", resolveVersion("", "(devel)", "unknown"))
	require.Equal(t, "unknown", resolveVersion("", "(devel)", ""))
	require.Equal(t, "unknown", resolveVersion("", "unknown", "unknown"))
}
