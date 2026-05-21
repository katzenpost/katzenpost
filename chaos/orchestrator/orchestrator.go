// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package orchestrator runs one iteration of the chaos property-based
// test loop. Each iteration is a self-contained mixnet lifecycle:
//
//  1. `make clean-local` against the docker dir tears down any prior
//     state, evicts persistence.db files, and removes the generated
//     compose so the next start regenerates configs from scratch.
//  2. `make start no_metrics=false kpclientd_metrics=true` brings a
//     fresh mixnet up under the bridge-network compose.
//  3. `make wait` blocks until the dirauths have a working consensus
//     and at least two storage replicas are registered.
//  4. The supplied chaos.Config is applied via the chaos package.
//  5. The full pigeonhole integration suite runs via
//     `cd client && make dockertest_all_pigeonhole`.
//  6. Prometheus snapshots are taken before, during, and after the
//     test run; the caller's invariant checks compare them.
//  7. `make clean-local` tears the mixnet down again, dropping all
//     state so the next iteration starts fresh.
//
// Each iteration is deliberately slow (full bring-up plus full test
// suite plus tear-down, on the order of 15 minutes) so the property
// fuzzer above can explore many distinct chaos configurations without
// state from one iteration bleeding into the next.
package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/katzenpost/katzenpost/chaos"
)

// Options collects every parameter that varies between iterations.
type Options struct {
	// RepoRoot is the absolute path to the katzenpost checkout.
	RepoRoot string

	// PrometheusURL is the base URL the orchestrator queries for
	// snapshots and invariant checks; default http://127.0.0.1:9090.
	PrometheusURL string

	// PigeonholeTarget is the client/Makefile target to invoke for
	// the test suite; default dockertest_all_pigeonhole.
	PigeonholeTarget string

	// MakeArgs are extra variables passed to make start. The
	// orchestrator always adds no_metrics=false and
	// kpclientd_metrics=true so prometheus is reachable.
	MakeArgs []string

	// MakeTimeout is the hard timeout for any single make
	// invocation; default 30m to accommodate the test suite.
	MakeTimeout time.Duration

	// SnapshotDir is the directory where per-iteration prometheus
	// snapshots are written; default os.TempDir().
	SnapshotDir string

	// Stdout / Stderr receive command output. nil discards.
	Stdout io.Writer
	Stderr io.Writer
}

// Result captures everything an invariant check or a PBT failure
// report needs to inspect a single iteration.
type Result struct {
	IterationLabel  string
	Started         time.Time
	Finished        time.Time
	Setup           StageResult
	ApplyChaos      StageResult
	TestSuite       StageResult
	Teardown        StageResult
	BeforeSnap      Snapshot
	DuringSnap      Snapshot
	AfterSnap       Snapshot
	ChaosConfigYAML string
}

// StageResult records the outcome of one orchestrator stage.
type StageResult struct {
	Stage     string
	StartedAt time.Time
	Duration  time.Duration
	Err       error
	// Output is the combined stdout+stderr of the stage command.
	// Bounded to a few MB so reproducer reports stay manageable.
	Output string
}

// Snapshot is the orchestrator's view of a single prometheus state
// capture at a moment in the iteration. The fields are the subset of
// metrics the invariant checks need; everything else is preserved as
// the raw Series map keyed by metric name.
type Snapshot struct {
	Taken                       time.Time
	DroppedPacketsTotal         float64
	DroppedInvalidTotal         float64
	DroppedDeadlineBlownTotal   float64
	DroppedRateLimitTotal       float64
	DroppedOutgoingTotal        float64
	ReplayedPacketsTotal        float64
	KaetzchenDroppedMixPackets  float64
	KaetzchenDroppedPackets     float64
	KaetzchenDroppedRequests    float64
	KaetzchenFailedRequests     float64
	CancelledOutgoingConns      float64
	// ReasonDrops is sum by (reason) for the labelled counter.
	ReasonDrops map[string]float64
	// CourierReasonDrops mirrors the above for the courier.
	CourierReasonDrops map[string]float64
	// SurbCreated/etc capture the client-side SURB lifecycle.
	SurbCreated     float64
	SurbGCed        float64
	SurbReplied     float64
	SurbReplyNoMatch float64
	// ARQInflight is the current gauge value.
	ARQInflight float64
	// CourierOldestAge is the max across replicas at snapshot time.
	CourierOldestAge float64
	// ConsensusReached is sum across dirauths.
	ConsensusReached float64
	CurrentEpoch     float64
}

// RunIteration drives one full iteration. The caller checks
// invariants by inspecting Result and the snapshot deltas.
func RunIteration(ctx context.Context, label string, chaosCfg *chaos.Config, opts Options) (*Result, error) {
	opts = withDefaults(opts)
	res := &Result{IterationLabel: label, Started: time.Now()}

	// Serialise the chaos config so a failing iteration's exact
	// reproducer is preserved alongside the result.
	if y, err := marshalChaosYAML(chaosCfg); err == nil {
		res.ChaosConfigYAML = y
	}

	// Setup: clean-local + start + wait. Bundle them in a single
	// make invocation; stop on the first failure.
	res.Setup = runMake(ctx, opts, "setup", append([]string{
		"clean-local", "start", "wait",
		"no_metrics=false", "kpclientd_metrics=true",
	}, opts.MakeArgs...)...)
	if res.Setup.Err != nil {
		res.Finished = time.Now()
		return res, fmt.Errorf("setup failed: %w", res.Setup.Err)
	}

	// Snapshot before chaos.
	if snap, err := readSnapshot(ctx, opts.PrometheusURL); err == nil {
		res.BeforeSnap = snap
	}
	writeSnapshotFile(opts, label+"_before", res.BeforeSnap)

	// Apply chaos. Empty config is allowed; it represents the
	// baseline lane in the PBT sweep.
	apply := StageResult{Stage: "apply", StartedAt: time.Now()}
	if chaosCfg != nil && len(chaosCfg.SortedHosts()) > 0 {
		applyErr := chaos.Apply(ctx, chaosCfg, chaos.DefaultRuntime())
		apply.Err = applyErr
	}
	apply.Duration = time.Since(apply.StartedAt)
	res.ApplyChaos = apply
	if apply.Err != nil {
		// Still attempt to tear the mixnet down.
		teardown(ctx, opts, res)
		res.Finished = time.Now()
		return res, fmt.Errorf("apply chaos failed: %w", apply.Err)
	}

	// Give pumba sidecars a few seconds to install qdiscs before
	// we start hammering the mixnet with tests.
	if chaosCfg != nil && len(chaosCfg.SortedHosts()) > 0 {
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
		}
	}

	// Run the full pigeonhole suite from client/.
	res.TestSuite = runClientMake(ctx, opts, "tests", opts.PigeonholeTarget)

	// Snapshot during chaos (taken after tests because the rate
	// queries need recent traffic to populate p50/p90/p99).
	if snap, err := readSnapshot(ctx, opts.PrometheusURL); err == nil {
		res.DuringSnap = snap
	}
	writeSnapshotFile(opts, label+"_during", res.DuringSnap)

	// Stop chaos cleanly so the after-snap captures the recovery
	// behaviour of the mixnet, not a still-running tc qdisc.
	_ = chaos.Clear(ctx, chaos.DefaultRuntime())
	select {
	case <-time.After(10 * time.Second):
	case <-ctx.Done():
	}

	if snap, err := readSnapshot(ctx, opts.PrometheusURL); err == nil {
		res.AfterSnap = snap
	}
	writeSnapshotFile(opts, label+"_after", res.AfterSnap)

	teardown(ctx, opts, res)
	res.Finished = time.Now()
	return res, nil
}

func teardown(ctx context.Context, opts Options, res *Result) {
	res.Teardown = runMake(ctx, opts, "teardown", "clean-local")
}

func withDefaults(opts Options) Options {
	if opts.PrometheusURL == "" {
		opts.PrometheusURL = "http://127.0.0.1:9090"
	}
	if opts.PigeonholeTarget == "" {
		opts.PigeonholeTarget = "dockertest_all_pigeonhole"
	}
	if opts.MakeTimeout == 0 {
		opts.MakeTimeout = 30 * time.Minute
	}
	if opts.SnapshotDir == "" {
		opts.SnapshotDir = os.TempDir()
	}
	if opts.RepoRoot == "" {
		// Best-effort discovery. The orchestrator is expected to be
		// called with an explicit RepoRoot in production.
		if wd, err := os.Getwd(); err == nil {
			opts.RepoRoot = wd
		}
	}
	return opts
}

func runMake(ctx context.Context, opts Options, stage string, args ...string) StageResult {
	stageRes := StageResult{Stage: stage, StartedAt: time.Now()}
	cctx, cancel := context.WithTimeout(ctx, opts.MakeTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "make", args...)
	cmd.Dir = filepath.Join(opts.RepoRoot, "docker")
	var buf bytes.Buffer
	if opts.Stdout != nil {
		cmd.Stdout = io.MultiWriter(&buf, opts.Stdout)
	} else {
		cmd.Stdout = &buf
	}
	if opts.Stderr != nil {
		cmd.Stderr = io.MultiWriter(&buf, opts.Stderr)
	} else {
		cmd.Stderr = &buf
	}
	err := cmd.Run()
	stageRes.Duration = time.Since(stageRes.StartedAt)
	stageRes.Err = err
	stageRes.Output = boundOutput(buf.String())
	return stageRes
}

func runClientMake(ctx context.Context, opts Options, stage string, args ...string) StageResult {
	stageRes := StageResult{Stage: stage, StartedAt: time.Now()}
	cctx, cancel := context.WithTimeout(ctx, opts.MakeTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "make", args...)
	cmd.Dir = filepath.Join(opts.RepoRoot, "client")
	var buf bytes.Buffer
	if opts.Stdout != nil {
		cmd.Stdout = io.MultiWriter(&buf, opts.Stdout)
	} else {
		cmd.Stdout = &buf
	}
	if opts.Stderr != nil {
		cmd.Stderr = io.MultiWriter(&buf, opts.Stderr)
	} else {
		cmd.Stderr = &buf
	}
	err := cmd.Run()
	stageRes.Duration = time.Since(stageRes.StartedAt)
	stageRes.Err = err
	stageRes.Output = boundOutput(buf.String())
	return stageRes
}

func boundOutput(s string) string {
	const max = 1 << 20 // 1 MiB
	if len(s) <= max {
		return s
	}
	return s[:max/2] + "\n...[truncated]...\n" + s[len(s)-max/2:]
}

func writeSnapshotFile(opts Options, label string, snap Snapshot) {
	path := filepath.Join(opts.SnapshotDir, fmt.Sprintf("snap_%s.json", label))
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, b, 0o644)
}

func marshalChaosYAML(cfg *chaos.Config) (string, error) {
	if cfg == nil {
		return "", nil
	}
	// Re-render via a deterministic ordering by lifting Hosts into a
	// sorted slice would be ideal; for the result file we just dump
	// the struct as YAML and accept yaml.v3's map ordering.
	return fmt.Sprintf("duration: %q\nhosts: %v\n", cfg.Duration, cfg.SortedHosts()), nil
}

// readSnapshot queries prometheus for every metric in the Snapshot
// struct via instant queries. The instant nature means each call
// captures point-in-time values, not rates; rate-style invariants are
// computed by the caller from before/during/after deltas.
func readSnapshot(ctx context.Context, base string) (Snapshot, error) {
	snap := Snapshot{
		Taken:              time.Now(),
		ReasonDrops:        map[string]float64{},
		CourierReasonDrops: map[string]float64{},
	}
	q := func(query string) (float64, map[string]float64, error) {
		return runQuery(ctx, base, query)
	}
	plainSums := []struct {
		query string
		out   *float64
	}{
		{"sum(katzenpost_dropped_packets_total)", &snap.DroppedPacketsTotal},
		{"sum(katzenpost_dropped_invalid_packets_total)", &snap.DroppedInvalidTotal},
		{"sum(katzenpost_dropped_deadline_blown_packets_total)", &snap.DroppedDeadlineBlownTotal},
		{"sum(katzenpost_dropped_rate_limit_total)", &snap.DroppedRateLimitTotal},
		{"sum(katzenpost_dropped_outgoing_packets_total)", &snap.DroppedOutgoingTotal},
		{"sum(katzenpost_replayed_packets_total)", &snap.ReplayedPacketsTotal},
		{"sum(katzenpost_kaetzchen_mix_packets_dropped_total)", &snap.KaetzchenDroppedMixPackets},
		{"sum(katzenpost_kaetzchen_dropped_packets_total)", &snap.KaetzchenDroppedPackets},
		{"sum(katzenpost_kaetzchen_dropped_requests_total)", &snap.KaetzchenDroppedRequests},
		{"sum(katzenpost_kaetzchen_failed_requests_total)", &snap.KaetzchenFailedRequests},
		{"sum(katzenpost_cancelled_outgoing_connections_total)", &snap.CancelledOutgoingConns},
		{"sum(katzenpost_client_surb_id_created_total)", &snap.SurbCreated},
		{"sum(katzenpost_client_surb_id_garbage_collected_total)", &snap.SurbGCed},
		{"sum(katzenpost_client_surb_id_reply_received_total)", &snap.SurbReplied},
		{"sum(katzenpost_client_surb_id_reply_no_match_total)", &snap.SurbReplyNoMatch},
		{"katzenpost_client_arq_inflight", &snap.ARQInflight},
		{"max(katzenpost_courier_oldest_age_seconds)", &snap.CourierOldestAge},
		{"sum(katzenpost_dirauth_consensus_reached_total)", &snap.ConsensusReached},
		{"avg(katzenpost_dirauth_current_epoch)", &snap.CurrentEpoch},
	}
	for _, ps := range plainSums {
		v, _, err := q(ps.query)
		if err == nil {
			*ps.out = v
		}
	}

	if _, m, err := q("sum by (reason) (katzenpost_dropped_reason_total)"); err == nil {
		snap.ReasonDrops = m
	}
	if _, m, err := q("sum by (reason) (katzenpost_courier_dropped_reason_total)"); err == nil {
		snap.CourierReasonDrops = m
	}

	return snap, nil
}

func runQuery(ctx context.Context, base, query string) (float64, map[string]float64, error) {
	u, err := url.Parse(base + "/api/v1/query")
	if err != nil {
		return 0, nil, err
	}
	q := u.Query()
	q.Set("query", query)
	u.RawQuery = q.Encode()
	req, _ := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var parsed struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Metric map[string]string `json:"metric"`
				Value  []any             `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return 0, nil, fmt.Errorf("prom: parse %s: %w", query, err)
	}
	if parsed.Status != "success" {
		return 0, nil, fmt.Errorf("prom: query %s returned status %s", query, parsed.Status)
	}
	if len(parsed.Data.Result) == 0 {
		return 0, map[string]float64{}, nil
	}

	byLabel := make(map[string]float64, len(parsed.Data.Result))
	var first float64
	for i, r := range parsed.Data.Result {
		var s string
		if len(r.Value) >= 2 {
			if v, ok := r.Value[1].(string); ok {
				s = v
			}
		}
		var fv float64
		_, err := fmt.Sscanf(s, "%g", &fv)
		if err != nil {
			continue
		}
		if i == 0 {
			first = fv
		}
		if reason, ok := r.Metric["reason"]; ok {
			byLabel[reason] = fv
		} else if job, ok := r.Metric["job"]; ok {
			byLabel[job] = fv
		}
	}
	return first, byLabel, nil
}

// Helper to ensure unused-import linters don't complain about the
// strings package once the file evolves.
var _ = strings.Join
