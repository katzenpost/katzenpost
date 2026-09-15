// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestJitterDelay(t *testing.T) {
	t.Parallel()

	require.Equal(t, time.Duration(0), JitterDelay(0))
	require.Equal(t, time.Duration(-5), JitterDelay(-5))

	base := 1000 * time.Millisecond
	sawBelow, sawAbove := false, false
	for i := 0; i < 200; i++ {
		got := JitterDelay(base)
		require.GreaterOrEqual(t, got, 500*time.Millisecond)
		require.Less(t, got, 1500*time.Millisecond)
		if got < base {
			sawBelow = true
		}
		if got > base {
			sawAbove = true
		}
	}
	require.True(t, sawBelow, "jitter never went below base")
	require.True(t, sawAbove, "jitter never went above base")
}
