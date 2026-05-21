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
		BeforeSnap: orchestrator.Snapshot{ConsensusReached: 5},
		AfterSnap:  orchestrator.Snapshot{ConsensusReached: 5},
	}
	out := ConsensusProgressed(r)
	require.False(t, out.Passed)
}

func TestNoSurbReplyNoMatchFailsOnNonZero(t *testing.T) {
	r := &orchestrator.Result{
		BeforeSnap: orchestrator.Snapshot{SurbReplyNoMatch: 0},
		AfterSnap:  orchestrator.Snapshot{SurbReplyNoMatch: 3},
	}
	out := NoSurbReplyNoMatch(r)
	require.False(t, out.Passed)
}

func TestSurbLifecycleBalancedAllowsSmallGap(t *testing.T) {
	r := &orchestrator.Result{
		AfterSnap: orchestrator.Snapshot{
			SurbCreated:    100,
			SurbGCed:       10,
			SurbReplied:    87,
			SurbReplyNoMatch: 0,
		},
	}
	out := SurbLifecycleBalanced(r)
	require.True(t, out.Passed) // 3 SURBs in flight = 3% leak ratio
}

func TestSurbLifecycleBalancedFailsOnLargeGap(t *testing.T) {
	r := &orchestrator.Result{
		AfterSnap: orchestrator.Snapshot{
			SurbCreated: 100,
			SurbReplied: 10,
		},
	}
	out := SurbLifecycleBalanced(r)
	require.False(t, out.Passed)
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
