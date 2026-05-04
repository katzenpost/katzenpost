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

func TestUnixDialerRoundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "dialer.sock")

	addr, err := net.ResolveUnixAddr("unix", sockPath)
	require.NoError(t, err)
	listener, err := net.ListenUnix("unix", addr)
	require.NoError(t, err)
	defer listener.Close()

	want := []byte("ping, unix")
	errCh := make(chan error, 1)
	go func() {
		serverConn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer serverConn.Close()
		buf := make([]byte, len(want))
		if _, err := io.ReadFull(serverConn, buf); err != nil {
			errCh <- err
			return
		}
		if string(buf) != string(want) {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		errCh <- nil
	}()

	cfg := &UnixDialConfig{Address: sockPath}
	conn, err := cfg.Dial()
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write(want)
	require.NoError(t, err)
	require.NoError(t, <-errCh)
}
