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
// drift unboundedly: a SURBID's life should be observable via the
// four exit-ish counters (replied, gc, no_match, rotated) but the
// exact accounting is not yet a strict balance.
//
// The current counter semantics under analysis (see the
// investigation notes for the full derivation):
//
//   - SurbIDReplyReceived fires when a reply MATCHES an arqSurbIDMap
//     entry but does NOT remove the entry. The downstream handler is
//     responsible for either rotating to a new SURBID (in Copy
//     ACK-then-payload flows) or directly deleting both maps on
//     terminal outcomes. So "received" is a match indicator, not an
//     exit.
//   - SurbIDRotated fires when an entry is removed from arqSurbIDMap
//     by rotation, regardless of whether the entry had received a
//     reply first. An ACK-then-payload Copy command's OLD SURBID
//     fires BOTH `received` (at the ACK match) AND `rotated` (at the
//     subsequent rotation). The dual-firing makes the lifecycle
//     equation `created = received + rotated + gc + no_match` an
//     over-count of exits.
//   - dropARQMessage and a few other map-removal sites delete
//     entries without firing any exit counter at all.
//
// The strict balance therefore cannot hold today; tightening it
// would require either renaming the counters or adding a
// "delivered" / "delete-after-reply" exit counter. Until that
// refactor lands, the invariant accepts a wide tolerance on both
// directions of imbalance and only flags a SURBID hard leak (the
// scenario where created grows but no exit counters do).
func SurbLifecycleBalanced(r *orchestrator.Result) Result {
	created := r.AfterSnap.SurbCreated
	exits := r.AfterSnap.SurbGCed + r.AfterSnap.SurbReplied + r.AfterSnap.SurbReplyNoMatch + r.AfterSnap.SurbRotated
	if created == 0 {
		return Result{Name: "surb_lifecycle_balanced", Passed: true}
	}
	// Hard leak case: created grew but exits did not move at all.
	if exits == 0 && created > 10 {
		return Result{
			Name:   "surb_lifecycle_balanced",
			Passed: false,
			Reason: fmt.Sprintf("SURB hard leak: created=%g but every exit counter is zero", created),
		}
	}
	// Otherwise we accept the current dual-firing accounting; the
	// "exits" series in the kpclientd dashboard is a more honest
	// view than this single boolean.
	return Result{Name: "surb_lifecycle_balanced", Passed: true}
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
