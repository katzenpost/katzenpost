// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package selfcheckcache

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"
)

func TestLoadReturnsErrNotFoundWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	want := &Result{
		NumCPU:             runtime.NumCPU(),
		OpsPerSecPerCore:   1.71,
		OpsPerSecSaturated: 10.52,
		IterationTime:      586 * time.Millisecond,
	}
	require.NoError(t, Save(dir, want))

	got, err := Load(dir)
	require.NoError(t, err)
	require.Equal(t, want.NumCPU, got.NumCPU)
	require.InDelta(t, want.OpsPerSecPerCore, got.OpsPerSecPerCore, 0.0001)
	require.InDelta(t, want.OpsPerSecSaturated, got.OpsPerSecSaturated, 0.0001)
	require.Equal(t, want.IterationTime, got.IterationTime)

	// Save stamps Hostname and MeasuredAt; the resulting file must
	// carry both so a future invalidation check can compare against
	// the live host.
	require.NotEmpty(t, got.Hostname)
	require.False(t, got.MeasuredAt.IsZero())
	require.WithinDuration(t, time.Now(), got.MeasuredAt, 10*time.Second)
}

func TestLoadRejectsStaleNumCPU(t *testing.T) {
	dir := t.TempDir()
	// Hand-craft a cached file whose NumCPU disagrees with the
	// current host so Load returns ErrStale.
	bad := &Result{
		Hostname:           hostnameOrEmpty(t),
		MeasuredAt:         time.Now().UTC(),
		NumCPU:             runtime.NumCPU() + 17, // guaranteed mismatch
		OpsPerSecPerCore:   1.0,
		OpsPerSecSaturated: 8.0,
		IterationTime:      time.Second,
	}
	writeRaw(t, dir, bad)

	_, err := Load(dir)
	require.ErrorIs(t, err, ErrStale)
}

func TestLoadRejectsStaleHostname(t *testing.T) {
	host, herr := os.Hostname()
	if herr != nil || host == "" {
		t.Skip("hostname unavailable, cannot exercise hostname staleness")
	}
	dir := t.TempDir()
	bad := &Result{
		Hostname:           host + ".elsewhere.invalid",
		MeasuredAt:         time.Now().UTC(),
		NumCPU:             runtime.NumCPU(),
		OpsPerSecPerCore:   1.0,
		OpsPerSecSaturated: 8.0,
		IterationTime:      time.Second,
	}
	writeRaw(t, dir, bad)

	_, err := Load(dir)
	require.ErrorIs(t, err, ErrStale)
}

func TestLoadCorruptFileSurfacesError(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(PathIn(dir), []byte("not = valid = toml ="), 0o600))
	_, err := Load(dir)
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrNotFound))
	require.False(t, errors.Is(err, ErrStale))
}

func TestSaveAtomicallyReplaces(t *testing.T) {
	dir := t.TempDir()
	first := &Result{
		NumCPU:             runtime.NumCPU(),
		OpsPerSecPerCore:   1.0,
		OpsPerSecSaturated: 8.0,
		IterationTime:      time.Second,
	}
	require.NoError(t, Save(dir, first))

	second := &Result{
		NumCPU:             runtime.NumCPU(),
		OpsPerSecPerCore:   2.0,
		OpsPerSecSaturated: 16.0,
		IterationTime:      500 * time.Millisecond,
	}
	require.NoError(t, Save(dir, second))

	got, err := Load(dir)
	require.NoError(t, err)
	require.InDelta(t, 2.0, got.OpsPerSecPerCore, 0.0001)
	require.InDelta(t, 16.0, got.OpsPerSecSaturated, 0.0001)
	require.Equal(t, 500*time.Millisecond, got.IterationTime)

	// No leftover temp files from the atomic-replace dance.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		require.Equal(t, FileName, e.Name(), "unexpected file in DataDir: %s", e.Name())
	}
}

func TestPathInIsUnderDataDir(t *testing.T) {
	dir := t.TempDir()
	require.Equal(t, filepath.Join(dir, FileName), PathIn(dir))
}

// writeRaw bypasses Save's provenance stamping so a test can plant
// a deliberately-stale cache file with whatever hostname and
// NumCPU it wants.
func writeRaw(t *testing.T, dir string, r *Result) {
	t.Helper()
	f, err := os.Create(PathIn(dir))
	require.NoError(t, err)
	require.NoError(t, toml.NewEncoder(f).Encode(r))
	require.NoError(t, f.Close())
}

func hostnameOrEmpty(t *testing.T) string {
	t.Helper()
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}
