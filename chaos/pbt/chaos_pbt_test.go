// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build chaos_pbt
// +build chaos_pbt

// TestChaosProperties is gated behind the chaos_pbt build tag because
// each iteration brings up a fresh docker-compose mixnet, runs the
// full pigeonhole test suite, and tears it back down. A single
// iteration takes on the order of fifteen minutes. The test is not
// part of the normal `go test ./...` sweep; invoke it explicitly:
//
//	cd chaos/pbt && go test -tags chaos_pbt -v -timeout 24h \
//	    -count=1 -run TestChaosProperties
//
// Operator knobs (environment variables):
//
//	CHAOS_PBT_ITERATIONS   number of distinct mixnet configurations
//	                       to run (default 4)
//	CHAOS_PBT_SEED         RNG seed for the generator (default 0,
//	                       which lets gopter pick its own)
//	CHAOS_PBT_REPO_ROOT    repo root path (default the test's cwd
//	                       walked up to the parent of go.mod)
//	CHAOS_PBT_SHRINK       1 to enable shrinking on failure (the
//	                       shrinker re-runs the orchestrator until
//	                       it finds a minimal reproducer; disabled
//	                       by default because each iteration is
//	                       fifteen minutes)
package pbt

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"

	"github.com/katzenpost/katzenpost/chaos"
	"github.com/katzenpost/katzenpost/chaos/invariant"
	"github.com/katzenpost/katzenpost/chaos/orchestrator"
)

func TestChaosProperties(t *testing.T) {
	repoRoot := envOr("CHAOS_PBT_REPO_ROOT", findRepoRoot(t))
	if repoRoot == "" {
		t.Fatal("could not determine repo root; set CHAOS_PBT_REPO_ROOT")
	}

	iters := envInt("CHAOS_PBT_ITERATIONS", 4)
	seed := envInt("CHAOS_PBT_SEED", 0)
	shrink := envInt("CHAOS_PBT_SHRINK", 0)

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = iters
	if shrink > 0 {
		parameters.MaxShrinkCount = 5
	} else {
		parameters.MaxShrinkCount = 0
	}
	if seed != 0 {
		parameters.Rng.Seed(int64(seed))
	}

	properties := gopter.NewProperties(parameters)
	properties.Property("invariants hold under per-host chaos", prop.ForAll(
		func(cfg *chaos.Config) bool {
			label := fmt.Sprintf("pbt_%d", time.Now().UnixNano())
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			res, runErr := orchestrator.RunIteration(ctx, label, cfg, orchestrator.Options{
				RepoRoot:           repoRoot,
				PigeonholeCpScript: envOr("CHAOS_PBT_PIGEONHOLE_CP_SCRIPT", filepath.Join(repoRoot, "chaos/scripts/pigeonhole_cp_roundtrip.sh")),
				PigeonholeCpFileSizeBytes: envInt("CHAOS_PBT_PIGEONHOLE_CP_SIZE", 65536),
				Stdout:                    os.Stdout,
				Stderr:                    os.Stderr,
			})
			if runErr != nil {
				t.Logf("iteration %s: orchestrator error: %v", label, runErr)
				dumpReproducer(label, cfg, res)
				return false
			}
			results := invariant.CheckAll(res, invariant.Standard())
			anyFailed := false
			for _, inv := range results {
				if !inv.Passed {
					anyFailed = true
					t.Logf("iteration %s INVARIANT FAILED %s: %s", label, inv.Name, inv.Reason)
				}
			}
			if anyFailed {
				dumpReproducer(label, cfg, res)
				return false
			}
			t.Logf("iteration %s PASSED (%d hosts perturbed)", label, len(cfg.SortedHosts()))
			return true
		},
		ConfigGen(DefaultBounds()),
	))

	properties.TestingRun(t)
}

func dumpReproducer(label string, cfg *chaos.Config, res *orchestrator.Result) {
	dir := os.TempDir()
	path := filepath.Join(dir, "chaos_repro_"+label+".yaml")
	if cfg != nil {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("# reproducer for %s\n", label))
		sb.WriteString(fmt.Sprintf("duration: %q\n", cfg.Duration))
		sb.WriteString("hosts:\n")
		for _, h := range cfg.SortedHosts() {
			hc := cfg.Hosts[h]
			sb.WriteString(fmt.Sprintf("  %s:\n", h))
			if hc.LatencyMs != 0 {
				sb.WriteString(fmt.Sprintf("    latency_ms: %d\n", hc.LatencyMs))
			}
			if hc.JitterMs != 0 {
				sb.WriteString(fmt.Sprintf("    jitter_ms: %d\n", hc.JitterMs))
			}
			if hc.LossPct != 0 {
				sb.WriteString(fmt.Sprintf("    loss_pct: %g\n", hc.LossPct))
			}
			if hc.CorruptPct != 0 {
				sb.WriteString(fmt.Sprintf("    corrupt_pct: %g\n", hc.CorruptPct))
			}
			if hc.PauseForSec != 0 {
				sb.WriteString(fmt.Sprintf("    pause_for_sec: %d\n", hc.PauseForSec))
			}
		}
		_ = os.WriteFile(path, []byte(sb.String()), 0o644)
	}
	if res != nil && len(res.LogsOnFailure) > 0 {
		logPath := filepath.Join(dir, "chaos_repro_"+label+"_logs.txt")
		var sb strings.Builder
		for k, v := range res.LogsOnFailure {
			sb.WriteString("=== " + k + " ===\n")
			sb.WriteString(v)
			sb.WriteString("\n\n")
		}
		_ = os.WriteFile(logPath, []byte(sb.String()), 0o644)
	}
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func envInt(name string, fallback int) int {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

// findRepoRoot walks up from the cwd looking for go.mod.
func findRepoRoot(t *testing.T) string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}
