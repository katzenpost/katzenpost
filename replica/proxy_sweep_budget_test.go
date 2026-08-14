// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestProxyAttemptTimeoutDividesTheBudget pins the sweep budget rule:
// ProxyRequestTimeout covers a whole failover sweep, and what remains
// of it is divided among the candidates still to try.
//
// Spending the whole budget on the first candidate would leave nothing
// for the co-holder, so a single slow holder would end the sweep
// instead of failing over, which is the availability property the
// sweep exists for.
func TestProxyAttemptTimeoutDividesTheBudget(t *testing.T) {
	deadline := time.Now().Add(30 * time.Second)

	first := proxyAttemptTimeout(deadline, 2)
	require.Greater(t, first, 14*time.Second)
	require.LessOrEqual(t, first, 15*time.Second,
		"with two holders to try, the first gets half the budget")

	last := proxyAttemptTimeout(deadline, 1)
	require.Greater(t, last, 29*time.Second)
	require.LessOrEqual(t, last, 30*time.Second,
		"the final candidate may spend everything that is left")
}

// TestProxyAttemptTimeoutExhaustedBudget covers the end of the sweep:
// once the deadline has passed there is no time to give a candidate,
// and proxyToShardWithSlot must not take a worker slot to do nothing.
func TestProxyAttemptTimeoutExhaustedBudget(t *testing.T) {
	past := time.Now().Add(-time.Second)
	require.Zero(t, proxyAttemptTimeout(past, 2))
	require.Zero(t, proxyAttemptTimeout(past, 1))
}

// TestProxyAttemptTimeoutGuardsCandidateCount checks the divisor is
// never zero or negative, which would panic on the division.
func TestProxyAttemptTimeoutGuardsCandidateCount(t *testing.T) {
	deadline := time.Now().Add(10 * time.Second)
	require.Greater(t, proxyAttemptTimeout(deadline, 0), 9*time.Second)
	require.Greater(t, proxyAttemptTimeout(deadline, -3), 9*time.Second)
}
