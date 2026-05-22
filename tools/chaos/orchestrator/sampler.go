// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package orchestrator

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MidRunSample is one streamed snapshot taken while the pigeonhole
// tests are executing. The orchestrator records these on a fixed
// cadence so a counter that briefly spikes during the test (and is
// drained again before the final snapshot) is still visible in the
// reproducer report.
type MidRunSample struct {
	At   time.Time
	Snap Snapshot
}

// streamSamples spawns a goroutine that polls prometheus on the given
// cadence until ctx is done. The collected samples are returned by
// the close call. The first sample fires after one tick; the goroutine
// stops cleanly on ctx cancellation and never panics on prometheus
// errors (it simply omits the failing sample).
func streamSamples(ctx context.Context, base string, every time.Duration) (stop func() []MidRunSample) {
	out := make(chan []MidRunSample, 1)
	go func() {
		var samples []MidRunSample
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				out <- samples
				return
			case t := <-ticker.C:
				snap, err := readSnapshot(ctx, base)
				if err != nil {
					continue
				}
				snap.Taken = t
				samples = append(samples, MidRunSample{At: t, Snap: snap})
			}
		}
	}()
	return func() []MidRunSample { return <-out }
}

// dumpContainerLogs returns the last lines of each katzenpost
// container's log via the docker/podman runtime. It is best-effort;
// any single failed dump is replaced by its error message. The
// resulting map is keyed by container name.
//
// The orchestrator only calls this when the test stage failed, so the
// usual case still produces no log noise.
func dumpContainerLogs(ctx context.Context, runtime string, repoRoot string, perContainerLines int) map[string]string {
	if runtime == "" {
		runtime = "podman"
	}
	composeFile := filepath.Join(repoRoot, "docker", "voting_mixnet", "docker-compose.yml")
	listCmd := exec.CommandContext(ctx, runtime, "compose", "-f", composeFile, "ps", "--format", "{{.Name}}")
	out, err := listCmd.Output()
	if err != nil {
		return map[string]string{"_error": fmt.Sprintf("list containers: %v", err)}
	}
	names := splitAndTrim(string(out), "\n")
	sort.Strings(names)
	logs := map[string]string{}
	for _, name := range names {
		var buf bytes.Buffer
		dump := exec.CommandContext(ctx, runtime, "compose", "-f", composeFile, "logs", "--tail", fmt.Sprintf("%d", perContainerLines), name)
		dump.Stdout = &buf
		dump.Stderr = io.Discard
		if err := dump.Run(); err != nil {
			logs[name] = fmt.Sprintf("(log dump failed: %v)", err)
			continue
		}
		logs[name] = buf.String()
	}
	return logs
}

func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := parts[:0]
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}
