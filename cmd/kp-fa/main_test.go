// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright (C) 2026 Jacob Appelbaum

package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/rand"
)

func TestBoxIndexMatchesNextIndex(t *testing.T) {
	first, err := bacap.NewMessageBoxIndex(rand.Reader)
	require.NoError(t, err)
	s := boxes{first: first}
	step := first
	for k := uint64(0); k < 20; k++ {
		got, err := s.index(k)
		require.NoError(t, err)
		require.Equal(t, step, got, k)
		step, err = step.NextIndex()
		require.NoError(t, err)
	}
}

func TestRadioAliases(t *testing.T) {
	root := newRootCommand(context.Background())
	for alias, name := range map[string]string{
		"send":      "send",
		"broadcast": "send",
		"on-air":    "send",
		"listen":    "listen",
		"tune-in":   "listen",
	} {
		cmd, _, err := root.Find([]string{alias})
		require.NoError(t, err, alias)
		require.Equal(t, name, cmd.Name(), alias)
	}
}

func TestRefusesWindowBelowOne(t *testing.T) {
	for _, w := range []string{"0", "-1"} {
		for _, sub := range [][]string{{"send"}, {"listen", "00"}} {
			root := newRootCommand(context.Background())
			root.SetArgs(append([]string{"-c", "/nonexistent/thinclient.toml", "--window", w}, sub...))
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)
			require.ErrorContains(t, root.Execute(), "--window", w, sub)
		}
	}
}

func TestReadCapFileIsNew(t *testing.T) {
	dir := t.TempDir()
	fresh := filepath.Join(dir, "fresh")
	f, err := createReadCapFile(fresh)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	fi, err := os.Stat(fresh)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())

	shared := filepath.Join(dir, "shared")
	require.NoError(t, os.WriteFile(shared, []byte("old"), 0o644))
	require.NoError(t, os.Chmod(shared, 0o644))
	_, err = createReadCapFile(shared)
	require.Error(t, err)

	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(target, link))
	_, err = createReadCapFile(link)
	require.Error(t, err)
	require.NoFileExists(t, target)
}

func TestRefusesNonPositiveStallTimeout(t *testing.T) {
	for _, d := range []string{"0s", "-1s"} {
		root := newRootCommand(context.Background())
		root.SetArgs([]string{"-c", "/nonexistent/thinclient.toml", "listen", "--stall-timeout", d, "00"})
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		require.ErrorContains(t, root.Execute(), "--stall-timeout", d)
	}
}
