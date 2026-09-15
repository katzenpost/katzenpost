// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package pbt holds the gopter generators and the property-based
// chaos test that drives the orchestrator. The package is purely
// computational; it is the test file (under a build tag) that
// actually starts mixnets.
package pbt

import (
	"reflect"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"

	"github.com/katzenpost/katzenpost/tools/chaos"
)

// Bounds collects the parameter ranges the generator samples from.
// They are exposed so a particular run can narrow the search space
// (e.g. a follow-up after a failure to investigate a specific lane).
type Bounds struct {
	// HostInclusionProb is the per-host probability of being
	// perturbed in a given iteration. 0.0 means baseline only;
	// 1.0 means every host gets some chaos every time.
	HostInclusionProb float64

	// LatencyMs is the [min, max] sampled when a host gains a
	// delay primitive.
	LatencyMin, LatencyMax int

	// JitterFractionMax is the maximum jitter as a fraction of
	// latency (e.g. 0.5 means jitter <= latency/2).
	JitterFractionMax float64

	// LossMaxPct caps random loss; 5 means at most 5%.
	LossMaxPct float64

	// CorruptMaxPct caps random bit-corruption; 0.05 means at
	// most 0.05% (extremely rare, but exercises the MAC path).
	CorruptMaxPct float64

	// PauseProb is the per-host probability of being paused
	// outright. 0.0 disables pause; 0.05 means about one host
	// in twenty gets paused per iteration. When pause is selected
	// the netem primitives for that host are skipped (chaos.Plan
	// enforces this).
	PauseProb float64

	// PauseMinSec, PauseMaxSec bound the pause duration.
	PauseMinSec, PauseMaxSec int

	// Duration is the YAML-level duration that applies to every
	// netem qdisc in the generated config. Pumba self-destructs the
	// qdisc after this, so a forgotten chaos run never lingers.
	Duration string
}

// DefaultBounds returns a sensible exploration envelope. The defaults
// keep latency near the Namenlos production range and packet loss
// modest, while leaving room for the occasional extreme value via the
// gopter shrinker.
func DefaultBounds() Bounds {
	return Bounds{
		HostInclusionProb: 0.35,
		LatencyMin:        10,
		LatencyMax:        400,
		JitterFractionMax: 0.5,
		LossMaxPct:        3.0,
		CorruptMaxPct:     0.02,
		PauseProb:         0.05,
		PauseMinSec:       5,
		PauseMaxSec:       30,
		Duration:          "5m",
	}
}

// HostChaosGen produces a HostChaos for a single host. It may return
// an empty HostChaos (meaning "no chaos for this host this iteration")
// according to the HostInclusionProb.
func HostChaosGen(b Bounds) gopter.Gen {
	return func(p *gopter.GenParameters) *gopter.GenResult {
		// Roll a single uniform [0,1] and pick the chaos shape.
		include := p.Rng.Float64() < b.HostInclusionProb
		if !include {
			return gopter.NewEmptyResult(reflect.TypeOf(chaos.HostChaos{}))
		}
		// Pause is mutually exclusive with netem on the same host,
		// so decide that first.
		if p.Rng.Float64() < b.PauseProb {
			secs := b.PauseMinSec + p.Rng.Intn(b.PauseMaxSec-b.PauseMinSec+1)
			return gopter.NewGenResult(chaos.HostChaos{PauseForSec: secs}, gopter.NoShrinker)
		}
		var hc chaos.HostChaos
		// Exactly one netem primitive per host. pumba realises delay,
		// loss and corrupt as separate root qdiscs and tc rejects a
		// second one on the same interface, so they are mutually
		// exclusive (Config.Validate enforces this). One categorical
		// draw, weighted delay-heavy and corrupt-rare; jitter rides on
		// delay and so is not a separate primitive.
		switch r := p.Rng.Float64(); {
		case r < 0.70:
			lat := b.LatencyMin + p.Rng.Intn(b.LatencyMax-b.LatencyMin+1)
			hc.LatencyMs = lat
			if p.Rng.Float64() < 0.6 {
				hc.JitterMs = int(float64(lat) * p.Rng.Float64() * b.JitterFractionMax)
			}
		case r < 0.95:
			hc.LossPct = p.Rng.Float64() * b.LossMaxPct
		default:
			hc.CorruptPct = p.Rng.Float64() * b.CorruptMaxPct
		}
		if hc.IsEmpty() {
			// A zero-width bound (e.g. LossMaxPct == 0) can yield an
			// empty draw; force a delay so a selected host always
			// carries exactly one primitive.
			lat := b.LatencyMin + p.Rng.Intn(b.LatencyMax-b.LatencyMin+1)
			hc = chaos.HostChaos{LatencyMs: lat}
		}
		return gopter.NewGenResult(hc, gopter.NoShrinker)
	}
}

// ConfigGen returns a generator for a full chaos.Config, with one
// HostChaos per known host and the duration plumbed through.
func ConfigGen(b Bounds) gopter.Gen {
	hosts := chaos.AllHosts
	hostGen := HostChaosGen(b)
	return func(p *gopter.GenParameters) *gopter.GenResult {
		cfg := &chaos.Config{
			Duration: b.Duration,
			Hosts:    make(map[string]chaos.HostChaos, len(hosts)),
		}
		for _, h := range hosts {
			res := hostGen(p)
			if res == nil {
				continue
			}
			v, ok := res.Retrieve()
			if !ok {
				continue
			}
			hc, ok := v.(chaos.HostChaos)
			if !ok {
				continue
			}
			cfg.Hosts[h] = hc
		}
		return gopter.NewGenResult(cfg, gopter.NoShrinker)
	}
}

// Common gopter primitive generators in case bespoke property
// suites want to compose against them.
var (
	_ = gen.Float64Range // referenced so unused-import lint is quiet
)
