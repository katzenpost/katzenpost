// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Wilson bounds checked against published values, because an interval that
// is quietly wrong would make every claim built on it wrong too.
func TestWilsonInterval(t *testing.T) {
	lo, hi := wilson(0, 100)
	require.InDelta(t, 0.0, lo, 1e-9, "zero failures cannot give a positive lower bound")
	require.InDelta(t, 0.03700, hi, 1e-4)

	lo, hi = wilson(50, 100)
	require.InDelta(t, 0.40383, lo, 1e-4)
	require.InDelta(t, 0.59617, hi, 1e-4)

	lo, hi = wilson(100, 100)
	require.InDelta(t, 1.0, hi, 1e-9, "all failures cannot give an upper bound below one")
	require.Greater(t, lo, 0.96)

	lo, hi = wilson(0, 0)
	require.Zero(t, lo)
	require.Zero(t, hi)
}

// The interval must widen as evidence thins, and must bracket the point
// estimate in every case.
func TestWilsonWidensWithLessData(t *testing.T) {
	_, wideHi := wilson(1, 10)
	_, narrowHi := wilson(100, 1000)
	require.Greater(t, wideHi, narrowHi)

	for _, c := range []struct{ k, n int }{{0, 5}, {1, 5}, {3, 17}, {17, 17}} {
		lo, hi := wilson(c.k, c.n)
		p := float64(c.k) / float64(c.n)
		require.LessOrEqual(t, lo, p)
		require.GreaterOrEqual(t, hi, p)
	}
}

func TestDiffInterval(t *testing.T) {
	// Identical proportions: the interval must straddle zero.
	lo, hi := diffInterval(10, 100, 10, 100)
	require.Less(t, lo, 0.0)
	require.Greater(t, hi, 0.0)

	// A large, well-evidenced gap must exclude zero.
	lo, _ = diffInterval(400, 1000, 10, 1000)
	require.Greater(t, lo, 0.0)

	// The same gap on thin evidence must not.
	lo, hi = diffInterval(4, 10, 1, 10)
	require.Less(t, lo, 0.0)
	require.Greater(t, hi, 0.0)

	lo, hi = diffInterval(1, 0, 1, 10)
	require.Zero(t, lo)
	require.Zero(t, hi)
}

// synthesise builds observations over a two-node-per-layer topology, dropping
// a packet with the per-node probability given. Routes mirror the real shape:
// gateway, three mixes, service, then three mixes and the gateway again.
func synthesise(t *testing.T, n int, drop map[string]float64, seed int64) []observation {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	layers := [][]string{{"l1a", "l1b"}, {"l2a", "l2b"}, {"l3a", "l3b"}}

	obs := make([]observation, 0, n)
	for i := 0; i < n; i++ {
		fwd := []string{"gw"}
		back := []string{}
		for _, layer := range layers {
			fwd = append(fwd, layer[rng.Intn(2)])
		}
		fwd = append(fwd, "svc")
		for _, layer := range layers {
			back = append(back, layer[rng.Intn(2)])
		}
		back = append(back, "gw")

		// One roll per traversal, as above.
		ok := true
		for _, hop := range append(append([]string{}, fwd...), back...) {
			if rng.Float64() < drop[hop] {
				ok = false
			}
		}
		obs = append(obs, observation{
			at: time.Now().Add(time.Duration(i) * time.Second), ok: ok, forward: fwd, back: back,
		})
	}
	return obs
}

// A node dropping far more than its peer must be the one flagged, and its
// peer must not be.
func TestLayerContrastsFindsThePlantedNode(t *testing.T) {
	obs := synthesise(t, 4000, map[string]float64{"l2a": 0.15}, 1)

	cs := layerContrasts(obs, []string{"l2a", "l2b"})
	require.Len(t, cs, 2)

	byNode := map[string]contrast{}
	for _, c := range cs {
		byNode[c.node] = c
	}
	require.True(t, byNode["l2a"].worse(), "the planted node must be flagged")
	require.False(t, byNode["l2b"].worse(), "its healthy peer must not be")
	require.Greater(t, byNode["l2a"].rate, byNode["l2b"].rate)
}

// Under uniform loss nobody is at fault, so flags here are false ones. A 95%
// interval is built to produce them 5% of the time and asserting none would
// be asserting the interval is wrong; what matters is that the rate stays near
// nominal rather than the estimator finding a culprit wherever it looks.
func TestLayerContrastsFalsePositiveRateIsNominal(t *testing.T) {
	uniform := map[string]float64{}
	for _, n := range []string{"gw", "svc", "l1a", "l1b", "l2a", "l2b", "l3a", "l3b"} {
		uniform[n] = 0.02
	}
	comparisons, flagged := 0, 0
	for seed := int64(1); seed <= 60; seed++ {
		obs := synthesise(t, 4000, uniform, seed)
		for _, layer := range [][]string{{"l1a", "l1b"}, {"l2a", "l2b"}, {"l3a", "l3b"}} {
			for _, c := range layerContrasts(obs, layer) {
				comparisons++
				if c.worse() {
					flagged++
				}
			}
		}
	}
	rate := float64(flagged) / float64(comparisons)
	require.Less(t, rate, 0.10,
		"false positive rate %.1f%% (%d of %d) is well above the nominal 5%%",
		100*rate, flagged, comparisons)
}

// Nodes on every route must be named as inseparable rather than silently
// omitted, so a reader does not read their absence as innocence.
func TestReportNamesTheInseparableNodes(t *testing.T) {
	obs := synthesise(t, 200, map[string]float64{"l1a": 0.3}, 7)
	a := new(attribution)
	for _, o := range obs {
		a.record(o)
	}
	buf := new(bytes.Buffer)
	a.reportNotSeparable(buf, obs, nil)
	require.Contains(t, buf.String(), "gw")
	require.Contains(t, buf.String(), "svc")
	require.Contains(t, buf.String(), "not separable")
}

// A clean run must print nothing at all: statistics about zero failures are
// noise.
func TestReportSilentWhenNothingFailed(t *testing.T) {
	a := new(attribution)
	for i := 0; i < 50; i++ {
		a.record(observation{at: time.Now(), ok: true, forward: []string{"gw", "l1a"}})
	}
	buf := new(bytes.Buffer)
	a.report(buf, nil)
	require.Empty(t, buf.String())
}

// Episodic loss must survive the summary. A burst confined to one stretch of
// the run must show up as a bucket far above the others rather than being
// averaged into the whole.
func TestReportOverTimeShowsAnEpisode(t *testing.T) {
	a := new(attribution)
	base := time.Now()
	for i := 0; i < 1000; i++ {
		// A burst of near-total loss between packets 600 and 700.
		ok := !(i >= 600 && i < 700)
		a.record(observation{
			at: base.Add(time.Duration(i) * time.Second), ok: ok,
			forward: []string{"gw", "l1a"}, back: []string{"l1a", "gw"},
		})
	}
	buf := new(bytes.Buffer)
	a.reportOverTime(buf, a.obs)
	out := buf.String()
	require.Contains(t, out, "failures over time")
	require.Contains(t, out, "100.0%", "the burst window should read as total loss")
	require.Contains(t, out, "  0.0%", "quiet windows should read as none")
}

// simulateVarying builds a run in which a node's drop probability may change
// partway through, which is the case the whole-run comparison cannot see.
func simulateVarying(seed int64, n int, dropAt func(i int, node string) float64) []observation {
	rng := rand.New(rand.NewSource(seed))
	layers := [][]string{{"l1a", "l1b"}, {"l2a", "l2b"}, {"l3a", "l3b"}}
	obs := make([]observation, 0, n)
	base := time.Now()
	for i := 0; i < n; i++ {
		fwd := []string{"gw"}
		back := []string{}
		for _, l := range layers {
			fwd = append(fwd, l[rng.Intn(2)])
		}
		fwd = append(fwd, "svc")
		for _, l := range layers {
			back = append(back, l[rng.Intn(2)])
		}
		back = append(back, "gw")

		// One roll per traversal: a node that drops packets does so each
		// time it handles one, so a route meeting it twice risks it twice.
		ok := true
		for _, hop := range append(append([]string{}, fwd...), back...) {
			if rng.Float64() < dropAt(i, hop) {
				ok = false
			}
		}
		obs = append(obs, observation{
			at: base.Add(time.Duration(i) * time.Second), ok: ok, forward: fwd, back: back,
		})
	}
	return obs
}

func testGroups() []group {
	return []group{
		{"mix layer 1", []string{"l1a", "l1b"}},
		{"mix layer 2", []string{"l2a", "l2b"}},
		{"mix layer 3", []string{"l3a", "l3b"}},
	}
}

// When the culprit swaps identity halfway through, both nodes end the run
// with the same average and the whole-run comparison is blind. The windowed
// scan must see both, in their own halves.
func TestWindowScanSeesASwappingCulprit(t *testing.T) {
	drop := func(i int, n string) float64 {
		if i < 1500 && n == "l1a" {
			return 0.15
		}
		if i >= 1500 && n == "l1b" {
			return 0.15
		}
		return 0.004
	}
	obs := simulateVarying(1, 3000, drop)

	for _, c := range layerContrasts(obs, []string{"l1a", "l1b"}) {
		require.False(t, c.worse(),
			"whole-run comparison should be blind here; that is why windows exist")
	}

	named := map[string]bool{}
	for _, f := range scanWindows(obs, testGroups(), scanWindowCount(len(obs))) {
		named[f.c.node] = true
	}
	require.True(t, named["l1a"], "the first half's culprit must be found")
	require.True(t, named["l1b"], "the second half's culprit must be found")
}

// A node bad for only a small slice of the run is diluted to near-innocence
// in the average. The windowed scan must still find it.
func TestWindowScanSeesABriefEpisode(t *testing.T) {
	drop := func(i int, n string) float64 {
		if i >= 1450 && i < 1550 && n == "l2a" {
			return 0.70
		}
		return 0.004
	}
	found := 0
	for seed := int64(1); seed <= 20; seed++ {
		obs := simulateVarying(seed, 3000, drop)
		for _, f := range scanWindows(obs, testGroups(), scanWindowCount(len(obs))) {
			if f.c.node == "l2a" {
				found++
				break
			}
		}
	}
	// Half the time is the honest expectation for so brief an episode: a
	// hundred bad packets in three thousand is thin evidence however it is
	// sliced. The whole-run comparison manages under one time in ten.
	require.Greater(t, found, 8,
		"a node dropping 70%% for a thirtieth of the run should be caught about half the time")
}

// The scan must not invent culprits. Under uniform loss, and under a
// network-wide episode that lifts every node together, it must stay quiet
// despite testing many windows.
func TestWindowScanQuietWhenNobodyIsAtFault(t *testing.T) {
	uniform := func(i int, n string) float64 { return 0.02 }
	episode := func(i int, n string) float64 {
		if i >= 1800 && i < 2100 {
			return 0.35
		}
		return 0.004
	}
	for name, drop := range map[string]func(int, string) float64{
		"uniform loss": uniform, "network-wide episode": episode,
	} {
		flagged := 0
		for seed := int64(1); seed <= 20; seed++ {
			flagged += len(scanWindows(simulateVarying(seed, 3000, drop), testGroups(), scanWindowCount(3000)))
		}
		require.LessOrEqual(t, flagged, 1, "%s: scan should stay quiet, got %d", name, flagged)
	}
}

// The multiple-comparison correction must actually tighten as more tests are
// made, or the scan would simply be a licence to find something.
func TestZForTestsTightensWithMoreComparisons(t *testing.T) {
	require.InDelta(t, zScore95, zForTests(1), 1e-3)
	require.Greater(t, zForTests(120), zForTests(1))
	require.Greater(t, zForTests(1000), zForTests(120))
	require.Equal(t, zForTests(1), zForTests(0))
}
