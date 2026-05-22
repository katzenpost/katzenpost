// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package chaos

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadFileValid(t *testing.T) {
	dir := t.TempDir()
	body := `
duration: 3m
hosts:
  mix1:
    latency_ms: 100
    jitter_ms: 30
  replica1:
    pause_for_sec: 20
  auth1:
    loss_pct: 0.5
  gateway1: {}
`
	path := filepath.Join(dir, "chaos.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	cfg, err := LoadFile(path)
	require.NoError(t, err)
	require.Equal(t, "3m", cfg.Duration)
	require.Equal(t, 100, cfg.Hosts["mix1"].LatencyMs)
	require.Equal(t, 30, cfg.Hosts["mix1"].JitterMs)
	require.Equal(t, 20, cfg.Hosts["replica1"].PauseForSec)
	require.InDelta(t, 0.5, cfg.Hosts["auth1"].LossPct, 1e-9)
	require.True(t, cfg.Hosts["gateway1"].IsEmpty())

	sorted := cfg.SortedHosts()
	require.Equal(t, []string{"auth1", "mix1", "replica1"}, sorted)
}

func TestLoadFileRejectsUnknownHost(t *testing.T) {
	dir := t.TempDir()
	body := `
hosts:
  not_a_real_host:
    latency_ms: 10
`
	path := filepath.Join(dir, "chaos.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	_, err := LoadFile(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown host")
}

func TestLoadFileRejectsMultipleNetemPrimitives(t *testing.T) {
	dir := t.TempDir()
	body := `
hosts:
  mix1:
    latency_ms: 100
    loss_pct: 5
`
	path := filepath.Join(dir, "chaos.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	_, err := LoadFile(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "netem primitives")
}

func TestLoadFileAllowsPauseWithIgnoredNetem(t *testing.T) {
	// pause is mutually exclusive with netem; Plan suppresses the
	// netem primitives, so the operator may declare both knowingly.
	dir := t.TempDir()
	body := `
hosts:
  replica1:
    pause_for_sec: 30
    latency_ms: 100
`
	path := filepath.Join(dir, "chaos.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	_, err := LoadFile(path)
	require.NoError(t, err)
}

func TestHostChaosIsEmpty(t *testing.T) {
	require.True(t, HostChaos{}.IsEmpty())
	require.False(t, HostChaos{LatencyMs: 1}.IsEmpty())
	require.False(t, HostChaos{LossPct: 0.1}.IsEmpty())
	require.False(t, HostChaos{PauseForSec: 1}.IsEmpty())
}
