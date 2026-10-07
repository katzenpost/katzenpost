// SPDX-License-Identifier: AGPL-3.0-only

package maxdelay

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEffectiveUnsetFallbackIsBuiltin(t *testing.T) {
	for _, fallback := range []int{0, -1} {
		limit, fromConsensus := Effective(0, fallback, time.Hour)
		require.False(t, fromConsensus)
		require.Equal(t, 27632*time.Millisecond, limit, "fallback %d", fallback)
	}
}

func TestEffectiveBuiltinStillBoundedByCeiling(t *testing.T) {
	limit, _ := Effective(0, 0, 10*time.Second)
	require.Equal(t, 10*time.Second, limit)
}

func TestEffectiveConfiguredFallback(t *testing.T) {
	limit, fromConsensus := Effective(0, 5000, time.Hour)
	require.False(t, fromConsensus)
	require.Equal(t, 5*time.Second, limit)
}

func TestEffectiveConsensusOverridesFallback(t *testing.T) {
	limit, fromConsensus := Effective(90000, 5000, time.Hour)
	require.True(t, fromConsensus)
	require.Equal(t, 90*time.Second, limit)
}
