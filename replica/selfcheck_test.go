// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"
)

// TestRunMKEMSelfCheckSmoke is a smoke test for runMKEMSelfCheck.
// CTIDH1024-X25519 Decapsulate is slow (~hundreds of ms per op), so
// the function takes single-digit seconds end-to-end; the test is
// kept tight by relying on the small mkemSelfCheckIterations and
// mkemSelfCheckSaturatedIterations constants in selfcheck.go.
//
// The three error paths inside runMKEMSelfCheck (GenerateKeyPair
// failure, rand.Read failure, solo Decapsulate failure) all return
// a zero-OpsPerSec MKEMSelfCheckResult with NumCPU still populated;
// downstream behaviour of that zero is exercised by
// TestApplyRuntimeDefaults in replica/config (cases
// "saturatedOpsPerSec=0 ... falls back to floors" and "negative
// saturatedOpsPerSec treated as 0"). Mocking the package-level
// MKEMNikeScheme to force the errors would require refactoring the
// production path to take an injectable scheme, which is more
// production complexity than the failure-mode coverage warrants.
//
// Note: this test must not call logging.SetBackend. Other tests in
// this package leak PKIWorker goroutines whose loggers read the
// go-logging library's package-global default backend; mutating
// that global from this test produced a data race against those
// readers when the full package was run under -race. The fix is
// to skip the global mutation and let the function under test
// write through whatever backend the default global has at the
// time. The test's assertions do not depend on captured log
// output.
func TestRunMKEMSelfCheckSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("CTIDH self-check takes several seconds; skipped under -short")
	}

	logger := logging.MustGetLogger("selfcheck-test")

	result := runMKEMSelfCheck(logger)

	require.Greater(t, result.NumCPU, 0, "NumCPU should be positive")
	require.Equal(t, runtime.NumCPU(), result.NumCPU, "NumCPU should match runtime")
	require.Greater(t, result.OpsPerSecPerCore, 0.0,
		"OpsPerSecPerCore should be positive on a successful run")
	require.Greater(t, result.OpsPerSecSaturated, 0.0,
		"OpsPerSecSaturated should be positive on a successful run")
	require.Greater(t, result.IterationTime.Nanoseconds(), int64(0),
		"IterationTime should be positive")

	// The saturated aggregate should never exceed the ideal
	// NumCPU * solo-rate by more than a small slack (timing noise,
	// the warmup having pre-paid into the second mode's data cache).
	idealAggregate := result.OpsPerSecPerCore * float64(result.NumCPU)
	require.LessOrEqual(t, result.OpsPerSecSaturated, idealAggregate*1.5,
		"saturated rate should not exceed 1.5x ideal numCPU * solo")
}
