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
