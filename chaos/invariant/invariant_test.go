// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package invariant

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/chaos/orchestrator"
)

func TestTestSuiteSucceededPasses(t *testing.T) {
	r := &orchestrator.Result{}
	out := TestSuiteSucceeded(r)
	require.True(t, out.Passed)
}

func TestTestSuiteSucceededFailsOnError(t *testing.T) {
	r := &orchestrator.Result{TestSuite: orchestrator.StageResult{Err: errors.New("kaboom")}}
	out := TestSuiteSucceeded(r)
	require.False(t, out.Passed)
	require.Contains(t, out.Reason, "kaboom")
}

func TestConsensusProgressedFailsWhenStuck(t *testing.T) {
	r := &orchestrator.Result{
		BeforeSnap: orchestrator.Snapshot{ConsensusReached: 5, CurrentEpoch: 100},
		AfterSnap:  orchestrator.Snapshot{ConsensusReached: 5, CurrentEpoch: 100},
	}
	out := ConsensusProgressed(r)
	require.False(t, out.Passed)
}

func TestConsensusProgressedPassesOnUnreachableSnap(t *testing.T) {
	// If after-snap couldn't reach prometheus, CurrentEpoch reads 0
	// and the invariant returns Passed with a diagnostic reason so
	// it doesn't fire spuriously alongside an unrelated test
	// failure.
	r := &orchestrator.Result{
		BeforeSnap: orchestrator.Snapshot{ConsensusReached: 5, CurrentEpoch: 100},
		AfterSnap:  orchestrator.Snapshot{ConsensusReached: 0, CurrentEpoch: 0},
	}
	out := ConsensusProgressed(r)
	require.True(t, out.Passed)
	require.Contains(t, out.Reason, "inconclusive")
}

func TestNoSurbReplyNoMatchFailsOnNonZero(t *testing.T) {
	r := &orchestrator.Result{
		BeforeSnap: orchestrator.Snapshot{SurbReplyNoMatch: 0},
		AfterSnap:  orchestrator.Snapshot{SurbReplyNoMatch: 3},
	}
	out := NoSurbReplyNoMatch(r)
	require.False(t, out.Passed)
}

func TestSurbLifecycleBalancedHealthy(t *testing.T) {
	r := &orchestrator.Result{
		AfterSnap: orchestrator.Snapshot{
			SurbCreated:      100,
			SurbGCed:         10,
			SurbReplied:      87,
			SurbReplyNoMatch: 0,
			SurbRotated:      0,
		},
	}
	require.True(t, SurbLifecycleBalanced(r).Passed)
}

func TestSurbLifecycleBalancedAcceptsDualFiring(t *testing.T) {
	// Dual-firing under current counter semantics: per Copy
	// ACK-then-payload, the OLD SURBID fires both `received` and
	// `rotated`. The invariant accepts this until the counters are
	// refactored to be strict exits-only.
	r := &orchestrator.Result{
		AfterSnap: orchestrator.Snapshot{
			SurbCreated: 100,
			SurbReplied: 80,
			SurbRotated: 90,
		},
	}
	require.True(t, SurbLifecycleBalanced(r).Passed)
}

func TestSurbLifecycleBalancedFailsOnHardLeak(t *testing.T) {
	r := &orchestrator.Result{
		AfterSnap: orchestrator.Snapshot{SurbCreated: 100},
	}
	out := SurbLifecycleBalanced(r)
	require.False(t, out.Passed)
	require.Contains(t, out.Reason, "hard leak")
}

func TestARQInflightBoundedFailsAboveLimit(t *testing.T) {
	r := &orchestrator.Result{AfterSnap: orchestrator.Snapshot{ARQInflight: 6000}}
	out := ARQInflightBounded(r)
	require.False(t, out.Passed)
}

func TestCourierOldestAgeRecoversFails(t *testing.T) {
	r := &orchestrator.Result{AfterSnap: orchestrator.Snapshot{CourierOldestAge: 90}}
	out := CourierOldestAgeRecovers(r)
	require.False(t, out.Passed)
}

func TestAllDropsHaveReasonLabel_PassWhenNoDrops(t *testing.T) {
	r := &orchestrator.Result{}
	require.True(t, AllDropsHaveReasonLabel(r).Passed)
}

func TestAllDropsHaveReasonLabel_FailWhenOnlyPlainIncrements(t *testing.T) {
	r := &orchestrator.Result{
		BeforeSnap: orchestrator.Snapshot{DroppedPacketsTotal: 0},
		AfterSnap:  orchestrator.Snapshot{DroppedPacketsTotal: 100},
	}
	out := AllDropsHaveReasonLabel(r)
	require.False(t, out.Passed)
}

func TestAllDropsHaveReasonLabel_PassWhenReasonMatches(t *testing.T) {
	r := &orchestrator.Result{
		BeforeSnap: orchestrator.Snapshot{
			DroppedPacketsTotal: 0,
			ReasonDrops:         map[string]float64{"queue_full": 0},
		},
		AfterSnap: orchestrator.Snapshot{
			DroppedPacketsTotal: 100,
			ReasonDrops:         map[string]float64{"queue_full": 80},
		},
	}
	out := AllDropsHaveReasonLabel(r)
	require.True(t, out.Passed)
}

func TestCheckAllRunsAll(t *testing.T) {
	r := &orchestrator.Result{
		AfterSnap: orchestrator.Snapshot{ConsensusReached: 5},
	}
	checks := []Invariant{TestSuiteSucceeded, ConsensusProgressed}
	results := CheckAll(r, checks)
	require.Len(t, results, 2)
	require.Equal(t, "test_suite_succeeded", results[0].Name)
	require.Equal(t, "consensus_progressed", results[1].Name)
}

func TestStandardSuiteShape(t *testing.T) {
	suite := Standard()
	require.NotEmpty(t, suite)
	require.GreaterOrEqual(t, len(suite), 5)
}
