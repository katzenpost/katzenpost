// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pbt

import (
	"math/rand"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/chaos"
)

// genConfigOnce draws one ChaosConfig with the given seed and bounds
// using gopter's machinery. The seed makes the test deterministic.
func genConfigOnce(t *testing.T, b Bounds, seed int64) *chaos.Config {
	t.Helper()
	p := &gopter.GenParameters{
		MinSize:        0,
		MaxSize:        100,
		Rng:            rand.New(rand.NewSource(seed)),
		MaxShrinkCount: 0,
	}
	res := ConfigGen(b)(p)
	v, ok := res.Retrieve()
	require.True(t, ok, "ConfigGen returned no value at seed %d", seed)
	cfg, ok := v.(*chaos.Config)
	require.True(t, ok)
	require.NoError(t, cfg.Validate())
	return cfg
}

func TestConfigGenStaysWithinBounds(t *testing.T) {
	b := DefaultBounds()
	for s := int64(1); s <= 20; s++ {
		cfg := genConfigOnce(t, b, s)
		for host, hc := range cfg.Hosts {
			if hc.LatencyMs != 0 {
				require.GreaterOrEqual(t, hc.LatencyMs, b.LatencyMin, "host %s seed %d", host, s)
				require.LessOrEqual(t, hc.LatencyMs, b.LatencyMax, "host %s seed %d", host, s)
			}
			if hc.JitterMs != 0 {
				require.LessOrEqual(t, hc.JitterMs, hc.LatencyMs, "jitter must be <= latency: host %s seed %d", host, s)
			}
			if hc.LossPct != 0 {
				require.LessOrEqual(t, hc.LossPct, b.LossMaxPct)
				require.GreaterOrEqual(t, hc.LossPct, 0.0)
			}
			if hc.CorruptPct != 0 {
				require.LessOrEqual(t, hc.CorruptPct, b.CorruptMaxPct)
			}
			if hc.PauseForSec != 0 {
				// pause must not coexist with netem on the same host
				require.Zero(t, hc.LatencyMs, "pause+latency on the same host violates exclusivity")
				require.Zero(t, hc.LossPct, "pause+loss on the same host violates exclusivity")
				require.Zero(t, hc.CorruptPct, "pause+corrupt on the same host violates exclusivity")
				require.GreaterOrEqual(t, hc.PauseForSec, b.PauseMinSec)
				require.LessOrEqual(t, hc.PauseForSec, b.PauseMaxSec)
			}
		}
	}
}

func TestConfigGenAtZeroInclusionGivesEmpty(t *testing.T) {
	b := DefaultBounds()
	b.HostInclusionProb = 0
	cfg := genConfigOnce(t, b, 42)
	require.Empty(t, cfg.SortedHosts(), "no host should have chaos at inclusion=0")
}

func TestConfigGenAtFullInclusionGivesEveryHost(t *testing.T) {
	b := DefaultBounds()
	b.HostInclusionProb = 1.0
	// Disable pause so we know every host carries netem.
	b.PauseProb = 0
	cfg := genConfigOnce(t, b, 7)
	require.Len(t, cfg.SortedHosts(), len(chaos.AllHosts))
}
