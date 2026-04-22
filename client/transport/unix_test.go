// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"io"
	"net"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnixListenerRoundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	cfg := &UnixListenConfig{Address: sockPath}
	l, err := cfg.Listen()
	require.NoError(t, err)
	defer l.Close()

	want := []byte("hello, unix")
	errCh := make(chan error, 1)
	go func() {
		conn, err := net.Dial("unix", sockPath)
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		if _, err := conn.Write(want); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	acceptedConn, err := l.Accept()
	require.NoError(t, err)
	defer acceptedConn.Close()

	got, err := io.ReadAll(&readUntilEOF{acceptedConn, len(want)})
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.NoError(t, <-errCh)
}

func TestListenConfigListen_Unix(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "dispatch.sock")

	cfg := &ListenConfig{Unix: &UnixListenConfig{Address: sockPath}}
	l, err := cfg.Listen()
	require.NoError(t, err)
	defer l.Close()

	require.Equal(t, "unix", l.Addr().Network())
	require.Equal(t, sockPath, l.Addr().String())
}

// readUntilEOF wraps a net.Conn and signals EOF after n bytes so
// io.ReadAll terminates. The thin-client framing layer uses a length
// prefix; the tests here do not, and need an explicit stopping rule.
type readUntilEOF struct {
	r         net.Conn
	remaining int
}

func (r *readUntilEOF) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if len(p) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.r.Read(p)
	r.remaining -= n
	if err == nil && r.remaining <= 0 {
		err = io.EOF
	}
	return n, err
}
