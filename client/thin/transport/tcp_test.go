// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTcpDialerRoundtrip(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	want := []byte("ping, tcp")
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

	cfg := &TcpDialConfig{Address: listener.Addr().String()}
	conn, err := cfg.Dial()
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write(want)
	require.NoError(t, err)
	require.NoError(t, <-errCh)
}

func TestTcpDialConfig_InvalidNetwork(t *testing.T) {
	cfg := &TcpDialConfig{Address: "127.0.0.1:1", Network: "udp"}
	conn, err := cfg.Dial()
	require.Nil(t, conn)
	require.Error(t, err)
	require.Contains(t, err.Error(), "udp")
}
