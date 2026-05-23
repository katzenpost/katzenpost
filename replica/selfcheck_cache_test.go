// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/selfcheckcache"
)

// TestLoadOrRunMKEMSelfCheckEnvVarSkipsLive proves that
// KATZENPOST_SKIP_SELFCHECK=1 short-circuits the live measurement
// and writes no sidecar, so a future boot without the env var
// would still measure. The check completes in milliseconds because
// it never touches CTIDH.
func TestLoadOrRunMKEMSelfCheckEnvVarSkipsLive(t *testing.T) {
	t.Setenv(SkipSelfCheckEnv, "1")
	dir := t.TempDir()
	logger := logging.MustGetLogger("loadorrun-envskip-test")

	start := time.Now()
	result := loadOrRunMKEMSelfCheck(logger, dir)
	elapsed := time.Since(start)

	// NumCPU still populated so ApplyRuntimeDefaults can pick its
	// NumCPU-only floors; saturated-ops/sec stays zero so the
	// floor branch is taken.
	require.Greater(t, result.NumCPU, 0)
	require.Zero(t, result.OpsPerSecPerCore)
	require.Zero(t, result.OpsPerSecSaturated)

	// No sidecar written: a zero measurement must not poison a
	// future boot that no longer sets the env var.
	_, err := os.Stat(selfcheckcache.PathIn(dir))
	require.ErrorIs(t, err, os.ErrNotExist)

	// Skip path must be fast (sub-second). A 1s margin keeps this
	// stable across CI hardware while catching a regression that
	// accidentally falls through to the live measurement.
	require.Less(t, elapsed, time.Second,
		"env-var skip path should be near-instant, took %s", elapsed)
}

func TestSkipSelfCheckRequestedRecognisesTruthyValues(t *testing.T) {
	truthy := []string{"1", "true", "TRUE", "True", "yes", "YES", "on", "ON", " true "}
	for _, v := range truthy {
		t.Run("truthy/"+v, func(t *testing.T) {
			t.Setenv(SkipSelfCheckEnv, v)
			require.True(t, skipSelfCheckRequested(), "value %q should be truthy", v)
		})
	}
	falsy := []string{"", "0", "false", "no", "off", "anything-else", "2"}
	for _, v := range falsy {
		t.Run("falsy/"+v, func(t *testing.T) {
			t.Setenv(SkipSelfCheckEnv, v)
			require.False(t, skipSelfCheckRequested(), "value %q should be falsy", v)
		})
	}
}

// TestLoadOrRunMKEMSelfCheckEnvVarYieldsToCache shows that a present
// sidecar wins over the env-var skip flag: the env var only
// suppresses the LIVE measurement; cached numbers are cheap to use
// and strictly better than the floor fallback, so we use them.
func TestLoadOrRunMKEMSelfCheckEnvVarYieldsToCache(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, selfcheckcache.Save(dir, &selfcheckcache.Result{
		NumCPU:             runtime.NumCPU(),
		OpsPerSecPerCore:   7.7,
		OpsPerSecSaturated: 55.5,
		IterationTime:      100 * time.Millisecond,
	}))

	t.Setenv(SkipSelfCheckEnv, "1")
	logger := logging.MustGetLogger("loadorrun-envskip-yields-test")

	start := time.Now()
	result := loadOrRunMKEMSelfCheck(logger, dir)
	elapsed := time.Since(start)

	require.InDelta(t, 7.7, result.OpsPerSecPerCore, 0.0001)
	require.InDelta(t, 55.5, result.OpsPerSecSaturated, 0.0001)
	require.Less(t, elapsed, time.Second)
}

// TestLoadOrRunMKEMSelfCheckUsesCache exercises the cached-second-boot
// path end-to-end. The first call has to run the live CTIDH self-check
// (single-digit seconds on a healthy host) and persist the result to
// the sidecar file. The second call must read that sidecar, return the
// same numbers, and complete in milliseconds rather than seconds because
// the cache means it skips the live measurement.
//
// The "cache hit is at least 10x faster than the live measurement" check
// is a deliberately loose contract: it confirms the cache is being
// honoured (rather than re-running the measurement under the covers)
// without depending on absolute durations that vary across CI hardware.
func TestLoadOrRunMKEMSelfCheckUsesCache(t *testing.T) {
	if testing.Short() {
		t.Skip("CTIDH self-check takes several seconds; skipped under -short")
	}

	dir := t.TempDir()
	logger := logging.MustGetLogger("loadorrun-cache-test")

	startFirst := time.Now()
	first := loadOrRunMKEMSelfCheck(logger, dir)
	firstDuration := time.Since(startFirst)
	require.Greater(t, first.NumCPU, 0)
	require.Greater(t, first.OpsPerSecPerCore, 0.0)
	require.Greater(t, first.OpsPerSecSaturated, 0.0)

	// The sidecar must exist after the first successful measurement.
	_, err := os.Stat(selfcheckcache.PathIn(dir))
	require.NoError(t, err, "selfcheck.toml should have been written")

	startSecond := time.Now()
	second := loadOrRunMKEMSelfCheck(logger, dir)
	secondDuration := time.Since(startSecond)

	// Cached values match the original measurement to the bit.
	require.Equal(t, first.NumCPU, second.NumCPU)
	require.Equal(t, first.OpsPerSecPerCore, second.OpsPerSecPerCore)
	require.Equal(t, first.OpsPerSecSaturated, second.OpsPerSecSaturated)
	require.Equal(t, first.IterationTime, second.IterationTime)

	// Cache-hit path must be dramatically faster than the live
	// measurement; a 10x margin keeps the test stable across CI
	// hardware while still catching a regression that accidentally
	// re-runs the live CTIDH path on every boot.
	require.Less(t, secondDuration*10, firstDuration,
		"cache hit (%s) should be at least 10x faster than live measurement (%s)",
		secondDuration, firstDuration)
}
