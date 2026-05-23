// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/selfcheckcache"
	"github.com/katzenpost/katzenpost/replica/instrument"
)

// SkipSelfCheckEnv is the environment variable an operator (or CI
// runner) sets to suppress the live CTIDH self-check measurement
// when no cached result is available. Recognised true values are
// "1", "true", "yes" and "on" (case-insensitive). An unset or
// empty value leaves the live measurement path enabled.
//
// A truthy env var does NOT override a present cache: if
// <DataDir>/selfcheck.toml exists and is valid for this host, the
// cached numbers are still used, since they are cheap to read and
// strictly better than the floor fallback. The env var only
// suppresses the LIVE measurement on a cache miss; it then returns
// a zero-saturated-ops/sec result so ApplyRuntimeDefaults falls
// back to its NumCPU-only floors. Useful for CI workflows where
// the saturated number cannot be measured honestly anyway because
// of shared-tenancy on small runners.
const SkipSelfCheckEnv = "KATZENPOST_SKIP_SELFCHECK"

// skipSelfCheckRequested returns true iff the environment variable
// is set to a value the operator means as "on".
func skipSelfCheckRequested() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(SkipSelfCheckEnv))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// loadOrRunMKEMSelfCheck returns the saturated and solo CTIDH MKEM
// measurement for this host. On first call for a given DataDir it
// runs the live self-check via runMKEMSelfCheck and persists the
// result to <DataDir>/selfcheck.toml; on subsequent calls (and
// across daemon restarts) it loads the cached result, so the
// replica daemon pays the multi-second CTIDH cost only once per
// host. The cache is invalidated automatically when runtime.NumCPU
// or the hostname changes; an operator forcing a fresh measurement
// (CPU upgrade, cgroup change) deletes the sidecar file by hand.
//
// The prometheus self-check gauges are always populated, whether
// the numbers came from a live measurement or from the cache, so
// the operator dashboards do not go dark on a cached boot.
//
// A failed measurement (OpsPerSecSaturated <= 0) is never cached,
// so a transient startup failure on one boot does not poison the
// next boot's tuning.
func loadOrRunMKEMSelfCheck(log *logging.Logger, dataDir string) MKEMSelfCheckResult {
	if cached, err := selfcheckcache.Load(dataDir); err == nil {
		log.Noticef(
			"CTIDH self-check: loaded cached measurement from %s "+
				"(NumCPU=%d, solo=%.2f ops/s/core, saturated=%.2f aggregate ops/s, "+
				"measured %s on host %q); skipping live self-check. "+
				"Delete the sidecar file to force a fresh measurement.",
			selfcheckcache.PathIn(dataDir),
			cached.NumCPU,
			cached.OpsPerSecPerCore,
			cached.OpsPerSecSaturated,
			cached.MeasuredAt.Format(time.RFC3339),
			cached.Hostname,
		)
		instrument.SelfCheckResults(cached.OpsPerSecPerCore, cached.OpsPerSecSaturated, cached.NumCPU)
		return MKEMSelfCheckResult{
			OpsPerSecPerCore:   cached.OpsPerSecPerCore,
			OpsPerSecSaturated: cached.OpsPerSecSaturated,
			NumCPU:             cached.NumCPU,
			IterationTime:      cached.IterationTime,
		}
	} else if !errors.Is(err, selfcheckcache.ErrNotFound) && !errors.Is(err, selfcheckcache.ErrStale) {
		log.Warningf(
			"self-check: cache at %s unreadable (%v); will re-measure and overwrite",
			selfcheckcache.PathIn(dataDir), err,
		)
	}

	// Env-var skip path: explicit operator (or CI) suppression of
	// the live measurement. We get NumCPU from the runtime so the
	// floor fallbacks in ApplyRuntimeDefaults still pick sensible
	// worker counts, but the saturated-ops/sec channel is left at
	// zero so the floor branch is taken. The cache is NOT written:
	// a zero measurement would mislead subsequent boots that no
	// longer set the env var.
	if skipSelfCheckRequested() {
		numCPU := runtime.NumCPU()
		log.Noticef(
			"CTIDH self-check: skipped on operator request via %s=%q "+
				"(NumCPU=%d, no live measurement, no cache written); "+
				"ApplyRuntimeDefaults will use NumCPU-only floors.",
			SkipSelfCheckEnv, os.Getenv(SkipSelfCheckEnv), numCPU,
		)
		return MKEMSelfCheckResult{NumCPU: numCPU}
	}

	result := runMKEMSelfCheck(log)
	if result.OpsPerSecSaturated <= 0 {
		log.Warning("self-check: measurement returned zero saturated ops/s; not caching")
		return result
	}
	cache := &selfcheckcache.Result{
		NumCPU:             result.NumCPU,
		OpsPerSecPerCore:   result.OpsPerSecPerCore,
		OpsPerSecSaturated: result.OpsPerSecSaturated,
		IterationTime:      result.IterationTime,
	}
	if err := selfcheckcache.Save(dataDir, cache); err != nil {
		log.Warningf(
			"self-check: failed to persist measurement to %s (%v); next boot will re-measure",
			selfcheckcache.PathIn(dataDir), err,
		)
		return result
	}
	log.Noticef("self-check: persisted measurement to %s", selfcheckcache.PathIn(dataDir))
	return result
}
