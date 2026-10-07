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

func TestWild(t *testing.T) {
	require.Equal(t, uint64(27632), BuiltinMs())
	for ms, wild := range map[uint64]bool{
		0:                true,
		6907:             true,
		6908:             false,
		27632:            false,
		110528:           false,
		110529:           true,
		^uint64(0):       true,
		^uint64(0) / 4:   true,
		^uint64(0)/4 + 1: true,
	} {
		require.Equal(t, wild, Wild(ms), "%d ms", ms)
	}
}
