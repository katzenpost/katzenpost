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

	first := proxyAttemptTimeout(deadline, 2, 0)
	require.Greater(t, first, 14*time.Second)
	require.LessOrEqual(t, first, 15*time.Second,
		"with two holders to try, the first gets half the budget")

	last := proxyAttemptTimeout(deadline, 1, 0)
	require.Greater(t, last, 29*time.Second)
	require.LessOrEqual(t, last, 30*time.Second,
		"the final candidate may spend everything that is left")
}

// TestProxyAttemptTimeoutExhaustedBudget covers the end of the sweep:
// once the deadline has passed there is no time to give a candidate,
// and proxyToShardWithSlot must not take a worker slot to do nothing.
func TestProxyAttemptTimeoutExhaustedBudget(t *testing.T) {
	past := time.Now().Add(-time.Second)
	require.Zero(t, proxyAttemptTimeout(past, 2, 0))
	require.Zero(t, proxyAttemptTimeout(past, 1, 0))
}

// TestProxyAttemptTimeoutGuardsCandidateCount checks the divisor is
// never zero or negative, which would panic on the division.
func TestProxyAttemptTimeoutGuardsCandidateCount(t *testing.T) {
	deadline := time.Now().Add(10 * time.Second)
	require.Greater(t, proxyAttemptTimeout(deadline, 0, 0), 9*time.Second)
	require.Greater(t, proxyAttemptTimeout(deadline, -3, 0), 9*time.Second)
}

// TestProxyAttemptTimeoutFloor covers the measured floor. Every attempt
// pays for one MKEM encapsulation before it starts waiting, so a share
// too small to cover that cannot succeed however it is spent. Starting
// it anyway would take a proxy worker slot and hold a core through a
// CTIDH1024 keygen and group action purely to arrive at a certain
// timeout, which is worse than not trying.
func TestProxyAttemptTimeoutFloor(t *testing.T) {
	// One saturated MKEM operation, measured on the docker replicas as
	// NumCPU/OpsPerSecSaturated = 8/2.78.
	const floor = 2900 * time.Millisecond

	// Comfortable share: granted in full.
	roomy := time.Now().Add(30 * time.Second)
	require.Greater(t, proxyAttemptTimeout(roomy, 2, floor), 14*time.Second)

	// A share that cannot cover the crypto is refused outright.
	tight := time.Now().Add(2 * time.Second)
	require.Zero(t, proxyAttemptTimeout(tight, 1, floor),
		"a share below one MKEM operation must not start an attempt")
	require.Zero(t, proxyAttemptTimeout(roomy, 20, floor),
		"splitting a budget too many ways must not start doomed attempts")

	// An unmeasured host gets no floor and the old behaviour.
	require.Greater(t, proxyAttemptTimeout(tight, 1, 0), time.Second,
		"a zero floor must not refuse anything")
}
