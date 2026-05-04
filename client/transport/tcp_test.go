// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTcpListenerRoundtrip(t *testing.T) {
	cfg := &TcpListenConfig{Address: "127.0.0.1:0"}
	l, err := cfg.Listen()
	require.NoError(t, err)
	defer l.Close()

	want := []byte("hello, tcp")
	errCh := make(chan error, 1)
	go func() {
		conn, err := net.Dial("tcp", l.Addr().String())
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

func TestTcpListenConfig_InvalidNetwork(t *testing.T) {
	cfg := &TcpListenConfig{Address: "127.0.0.1:0", Network: "udp"}
	l, err := cfg.Listen()
	require.Nil(t, l)
	require.Error(t, err)
	require.Contains(t, err.Error(), "udp")
}

func TestTcpListenConfig_ExplicitV4(t *testing.T) {
	cfg := &TcpListenConfig{Address: "127.0.0.1:0", Network: "tcp4"}
	l, err := cfg.Listen()
	require.NoError(t, err)
	defer l.Close()
	require.Equal(t, "tcp", l.Addr().Network())
}

func TestListenConfigListen_Tcp(t *testing.T) {
	cfg := &ListenConfig{Tcp: &TcpListenConfig{Address: "127.0.0.1:0"}}
	l, err := cfg.Listen()
	require.NoError(t, err)
	defer l.Close()
	require.Equal(t, "tcp", l.Addr().Network())
}
