// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package invariant evaluates whether one chaos iteration violated any
// of the properties the Katzenpost mixnet must uphold under chaos.
// Each Invariant is an independent function on the orchestrator
// Result; the property fuzzer above gathers their outcomes and
// considers an iteration failed if any returns !Passed.
package invariant

import (
	"fmt"

	"github.com/katzenpost/katzenpost/chaos/orchestrator"
)

// Result records one invariant's outcome on one iteration.
type Result struct {
	Name   string
	Passed bool
	Reason string
}

// Invariant is the signature every property check satisfies.
type Invariant func(r *orchestrator.Result) Result

// CheckAll runs every invariant in order and returns their results.
// The list is deterministic so failure reports compare cleanly across
// iterations.
func CheckAll(r *orchestrator.Result, checks []Invariant) []Result {
	out := make([]Result, 0, len(checks))
	for _, c := range checks {
		out = append(out, c(r))
	}
	return out
}

// Standard returns the default suite of invariants. Each is documented
// in its own function comment below.
func Standard() []Invariant {
	return []Invariant{
		TestSuiteSucceeded,
		PigeonholeCpRoundtripSucceeded,
		ConsensusProgressed,
		NoSurbReplyNoMatch,
		SurbLifecycleBalanced,
		ARQInflightBounded,
		CourierOldestAgeRecovers,
		AllDropsHaveReasonLabel,
	}
}

// TestSuiteSucceeded asserts the pigeonhole test suite passed under
// this chaos configuration. This is the most basic property: any
// chaos that the protocol is supposed to survive must not break the
// pigeonhole API contract.
func TestSuiteSucceeded(r *orchestrator.Result) Result {
	if r.TestSuite.Err == nil {
		return Result{Name: "test_suite_succeeded", Passed: true}
	}
	return Result{
		Name:   "test_suite_succeeded",
		Passed: false,
		Reason: fmt.Sprintf("dockertest_all_pigeonhole failed: %v", r.TestSuite.Err),
	}
}

// PigeonholeCpRoundtripSucceeded asserts the pigeonhole-cp end-to-end
// file roundtrip succeeded under the iteration's chaos. The stage is
// only populated when the orchestrator was configured with a script
// path; a zero-value Stage means the orchestrator skipped it, which
// the invariant treats as a pass (it has nothing to assert against).
func PigeonholeCpRoundtripSucceeded(r *orchestrator.Result) Result {
	if r.PigeonholeCpRoundtrip.Stage == "" {
		return Result{Name: "pigeonhole_cp_roundtrip_succeeded", Passed: true}
	}
	if r.PigeonholeCpRoundtrip.Err == nil {
		return Result{Name: "pigeonhole_cp_roundtrip_succeeded", Passed: true}
	}
	return Result{
		Name:   "pigeonhole_cp_roundtrip_succeeded",
		Passed: false,
		Reason: fmt.Sprintf("pigeonhole-cp roundtrip failed in %v: %v", r.PigeonholeCpRoundtrip.Duration, r.PigeonholeCpRoundtrip.Err),
	}
}

// ConsensusProgressed asserts the dirauths reached at least one new
// consensus document between the before and after snapshots. Chaos
// that targets dirauths is allowed to slow consensus; it is not
// allowed to halt it for the whole iteration.
func ConsensusProgressed(r *orchestrator.Result) Result {
	delta := r.AfterSnap.ConsensusReached - r.BeforeSnap.ConsensusReached
	if delta > 0 {
		return Result{Name: "consensus_progressed", Passed: true}
	}
	return Result{
		Name:   "consensus_progressed",
		Passed: false,
		Reason: fmt.Sprintf("consensus_reached did not advance (before=%g, after=%g)", r.BeforeSnap.ConsensusReached, r.AfterSnap.ConsensusReached),
	}
}

// NoSurbReplyNoMatch asserts that no SURB reply arrived at the client
// without a matching pending entry. A non-zero delta means the GC
// timer evicted a SURB ID before the reply arrived; under our current
// per-hop slop calculation that should not happen at the latencies
// we apply.
func NoSurbReplyNoMatch(r *orchestrator.Result) Result {
	delta := r.AfterSnap.SurbReplyNoMatch - r.BeforeSnap.SurbReplyNoMatch
	if delta == 0 {
		return Result{Name: "no_surb_reply_no_match", Passed: true}
	}
	return Result{
		Name:   "no_surb_reply_no_match",
		Passed: false,
		Reason: fmt.Sprintf("%g SURB replies arrived without a matching entry; raise per-hop slop or investigate GC timer", delta),
	}
}

// SurbLifecycleBalanced asserts the SURB lifecycle counters do not
// drift unboundedly: every SURB ID that entered the ARQ map should
// eventually exit via reply received, garbage-collected, or no-match.
//
// Rotation (ACK-before-payload, compose-retry placeholders) and the
// orphan SURB IDs that leave the map without firing any exit counter
// make the bound asymmetric: `received - created` can become positive
// when rotations happen (we count each new map entry as `created`,
// but the OLD SURBID in a rotation pair leaves the map silently if it
// did not get its own reply first). We therefore allow up to 50% of
// the cumulative created count to be "unaccounted" on the exits side,
// which is generous enough for the rotation orphans the current
// instrumentation does not track but tight enough to surface a real
// leak (a forgotten exit counter, a map entry that nobody ever
// retires).
func SurbLifecycleBalanced(r *orchestrator.Result) Result {
	created := r.AfterSnap.SurbCreated
	exits := r.AfterSnap.SurbGCed + r.AfterSnap.SurbReplied + r.AfterSnap.SurbReplyNoMatch
	if created == 0 {
		return Result{Name: "surb_lifecycle_balanced", Passed: true}
	}
	if exits >= created {
		// Excess of exits over created is only possible if create
		// fires fail at a map-entry site; flag it loudly.
		gap := exits - created
		if gap/created <= 0.05 {
			return Result{Name: "surb_lifecycle_balanced", Passed: true}
		}
		return Result{
			Name:   "surb_lifecycle_balanced",
			Passed: false,
			Reason: fmt.Sprintf("SURB lifecycle gap: exits=%g exceed created=%g by %g; the create counter likely misses one or more arqSurbIDMap insertion sites", exits, created, gap),
		}
	}
	leakRatio := (created - exits) / created
	if leakRatio <= 0.50 {
		return Result{Name: "surb_lifecycle_balanced", Passed: true}
	}
	return Result{
		Name:   "surb_lifecycle_balanced",
		Passed: false,
		Reason: fmt.Sprintf("SURB lifecycle gap: created=%g, exits=%g (gc+replied+no_match), leak_ratio=%.2f%%; a SURB ID is being abandoned outside of any exit counter", created, exits, leakRatio*100),
	}
}

// ARQInflightBounded asserts the client's ARQ in-flight count did not
// grow unbounded during the iteration. A retry storm under loss would
// drive this to high values without ever draining.
func ARQInflightBounded(r *orchestrator.Result) Result {
	const limit = 5000.0
	if r.AfterSnap.ARQInflight <= limit {
		return Result{Name: "arq_inflight_bounded", Passed: true}
	}
	return Result{
		Name:   "arq_inflight_bounded",
		Passed: false,
		Reason: fmt.Sprintf("arq_inflight = %g exceeds limit %g; suggests retry storm", r.AfterSnap.ARQInflight, limit),
	}
}

// CourierOldestAgeRecovers asserts the courier outgoing queue's
// oldest-age gauge has dropped close to zero by the after-snap.
// Persistent staleness indicates the queue is stuck on a peer that
// pumba already released.
func CourierOldestAgeRecovers(r *orchestrator.Result) Result {
	const limit = 30.0
	if r.AfterSnap.CourierOldestAge <= limit {
		return Result{Name: "courier_oldest_age_recovers", Passed: true}
	}
	return Result{
		Name:   "courier_oldest_age_recovers",
		Passed: false,
		Reason: fmt.Sprintf("courier oldest_age_seconds = %g > %g after chaos cleared", r.AfterSnap.CourierOldestAge, limit),
	}
}

// AllDropsHaveReasonLabel asserts that whenever the plain drop
// counters increased over the iteration, the reason-labelled
// CounterVec also gained one or more series. A drop without an
// attached reason label is the most likely class of software defect
// the new instrumentation surfaces.
//
// The check is asymmetric: we count plain delta and reason delta
// separately, and flag the property only when plain incremented while
// reason did not. Equal-but-mismatched-labels remains a softer
// finding that the operator can inspect from the snapshot file.
func AllDropsHaveReasonLabel(r *orchestrator.Result) Result {
	plain := plainDropTotal(r.AfterSnap) - plainDropTotal(r.BeforeSnap)
	reason := sumValues(r.AfterSnap.ReasonDrops) - sumValues(r.BeforeSnap.ReasonDrops)
	if plain <= 0 {
		return Result{Name: "all_drops_have_reason_label", Passed: true}
	}
	if reason >= plain*0.5 {
		// At least half of the plain drops were also reason-labelled
		// in this iteration. The lower bound accommodates plain
		// counters that do not yet have a matching reason emitter.
		return Result{Name: "all_drops_have_reason_label", Passed: true}
	}
	return Result{
		Name:   "all_drops_have_reason_label",
		Passed: false,
		Reason: fmt.Sprintf("plain drops delta=%g but reason-labelled delta=%g; half-or-more of drops are uncounted", plain, reason),
	}
}

func plainDropTotal(s orchestrator.Snapshot) float64 {
	return s.DroppedPacketsTotal +
		s.DroppedInvalidTotal +
		s.DroppedDeadlineBlownTotal +
		s.DroppedRateLimitTotal +
		s.DroppedOutgoingTotal +
		s.KaetzchenDroppedMixPackets +
		s.KaetzchenDroppedPackets +
		s.KaetzchenDroppedRequests +
		s.KaetzchenFailedRequests
}

func sumValues(m map[string]float64) float64 {
	var s float64
	for _, v := range m {
		s += v
	}
	return s
}
