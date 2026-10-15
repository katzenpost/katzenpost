// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright (C) 2026 Jacob Appelbaum

//go:build docker_test

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const dockerThinClientConfig = "testdata/thinclient.toml"

func runCLI(t *testing.T, in []byte, args ...string) (stdout, stderr string) {
	t.Helper()
	var out, status bytes.Buffer
	root := newRootCommand(context.Background())
	root.SetArgs(append([]string{"-c", dockerThinClientConfig}, args...))
	root.SetIn(bytes.NewReader(in))
	root.SetOut(&out)
	root.SetErr(&status)
	require.NoError(t, root.Execute(), status.String())
	return out.String(), status.String()
}

func TestDockerBroadcastTuneIn(t *testing.T) {
	clip := readClip(t)
	readCapFile := filepath.Join(t.TempDir(), "readcap")

	_, status := runCLI(t, clip, "broadcast", "--readcap-file", readCapFile)
	require.Contains(t, status, "end of broadcast sent, off the air")
	raw, err := os.ReadFile(readCapFile)
	require.NoError(t, err)
	readCap := strings.TrimSpace(string(raw))

	out, status := runCLI(t, nil, "tune-in", "--from-start", readCap)
	require.Equal(t, clip, []byte(out))
	require.Contains(t, status, "broadcast ended, signing off")

	out, status = runCLI(t, nil, "tune-in", readCap)
	require.Contains(t, status, "ended true, starting at box 1")
	require.Equal(t, clip, []byte(out))
	require.Contains(t, status, "broadcast ended, signing off")
}
