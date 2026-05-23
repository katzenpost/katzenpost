// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/selfcheckcache"
)

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
