// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package selfcheckcache persists the result of a daemon's startup
// self-check to a sidecar TOML file in the daemon's DataDir so a
// restart on the same hardware does not have to re-measure.
//
// Each daemon (replica, server) measures one operation type (CTIDH
// MKEM Decapsulate, Sphinx Unwrap, etc.) and the cost is dominated
// by the CPU rather than by which scheme is timed, so the cached
// fields are scheme-agnostic: NumCPU, solo and saturated ops/sec,
// and the per-op iteration time. A hostname is recorded so that a
// DataDir accidentally shared between hosts via network storage
// invalidates rather than poisons the cache, and a NumCPU mismatch
// invalidates the cache so a host that gained or lost cores
// re-measures rather than reusing a stale per-host ceiling.
//
// The file is written atomically (temp file plus rename) so a
// crash during writeback never leaves a partial sidecar behind.
package selfcheckcache

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/BurntSushi/toml"
)

// FileName is the basename of the sidecar TOML in DataDir.
const FileName = "selfcheck.toml"

// ErrNotFound is returned by Load when no sidecar exists yet.
var ErrNotFound = errors.New("selfcheckcache: no cached self-check found")

// ErrStale is returned by Load when the sidecar's hostname or
// NumCPU disagrees with the current host's, so the cached numbers
// no longer describe the same machine.
var ErrStale = errors.New("selfcheckcache: cached self-check is stale for this host")

// Result holds the persisted self-check measurement. Hostname and
// MeasuredAt are provenance fields recorded by Save; the four
// measurement fields are supplied by the caller.
type Result struct {
	Hostname           string
	MeasuredAt         time.Time
	NumCPU             int
	OpsPerSecPerCore   float64
	OpsPerSecSaturated float64
	IterationTime      time.Duration
}

// PathIn returns the absolute path of the sidecar file within
// the given DataDir. Exposed so callers can log it.
func PathIn(dataDir string) string {
	return filepath.Join(dataDir, FileName)
}

// Load reads the sidecar file from dataDir and returns its parsed
// Result if the cached hostname and NumCPU still match the running
// host. Callers should treat ErrNotFound and ErrStale as cues to
// run a fresh measurement and call Save afterwards; other errors
// (e.g. permission denied, corrupt TOML) are returned verbatim so
// the caller can decide whether to surface them.
func Load(dataDir string) (*Result, error) {
	path := PathIn(dataDir)
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("selfcheckcache: open %s: %w", path, err)
	}
	defer f.Close()

	buf, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("selfcheckcache: read %s: %w", path, err)
	}

	r := &Result{}
	if err := toml.Unmarshal(buf, r); err != nil {
		return nil, fmt.Errorf("selfcheckcache: parse %s: %w", path, err)
	}

	host, err := os.Hostname()
	if err != nil {
		host = ""
	}
	if host != "" && r.Hostname != "" && r.Hostname != host {
		return nil, fmt.Errorf("%w: cached hostname %q, current %q", ErrStale, r.Hostname, host)
	}
	if r.NumCPU != runtime.NumCPU() {
		return nil, fmt.Errorf("%w: cached NumCPU=%d, current NumCPU=%d", ErrStale, r.NumCPU, runtime.NumCPU())
	}

	return r, nil
}

// Save writes a new Result to the sidecar file in dataDir,
// stamping Hostname and MeasuredAt from the running host. The
// write is atomic: the data is first written to a temporary file
// in the same directory and then renamed into place, so a partial
// write never leaves a corrupt sidecar.
func Save(dataDir string, r *Result) error {
	if r == nil {
		return errors.New("selfcheckcache: Save called with nil Result")
	}
	r.Hostname, _ = os.Hostname()
	r.MeasuredAt = time.Now().UTC()

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("selfcheckcache: mkdir %s: %w", dataDir, err)
	}

	tmp, err := os.CreateTemp(dataDir, FileName+".*.tmp")
	if err != nil {
		return fmt.Errorf("selfcheckcache: create temp in %s: %w", dataDir, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := toml.NewEncoder(tmp).Encode(r); err != nil {
		tmp.Close()
		return fmt.Errorf("selfcheckcache: encode: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("selfcheckcache: fsync %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("selfcheckcache: close %s: %w", tmpPath, err)
	}

	dst := PathIn(dataDir)
	if err := os.Rename(tmpPath, dst); err != nil {
		return fmt.Errorf("selfcheckcache: rename %s -> %s: %w", tmpPath, dst, err)
	}
	return nil
}
