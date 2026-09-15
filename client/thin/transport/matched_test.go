// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package transport_test

import (
	"io"
	"net"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	daemontransport "github.com/katzenpost/katzenpost/client/transport"

	thintransport "github.com/katzenpost/katzenpost/client/thin/transport"
)

// TestMatchedUnix exercises the daemon-side Listener and the
// thin-client-side Dialer of the unix transport together, proving
// bytes written on one side arrive intact on the other and vice
// versa.
func TestMatchedUnix(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "matched.sock")

	listenCfg := &daemontransport.ListenConfig{
		Unix: &daemontransport.UnixListenConfig{Address: sockPath},
	}
	listener, err := listenCfg.Listen()
	require.NoError(t, err)
	defer listener.Close()

	dialCfg := &thintransport.DialConfig{
		Unix: &thintransport.UnixDialConfig{Address: sockPath},
	}

	assertBidirectional(t, listener, dialCfg)
}

// TestMatchedTcp does the same for the TCP transport over an
// ephemeral port.
func TestMatchedTcp(t *testing.T) {
	listenCfg := &daemontransport.ListenConfig{
		Tcp: &daemontransport.TcpListenConfig{Address: "127.0.0.1:0"},
	}
	listener, err := listenCfg.Listen()
	require.NoError(t, err)
	defer listener.Close()

	dialCfg := &thintransport.DialConfig{
		Tcp: &thintransport.TcpDialConfig{Address: listener.Addr().String()},
	}

	assertBidirectional(t, listener, dialCfg)
}

// assertBidirectional connects a client to a listener, writes a
// canary in each direction, and verifies the far side receives it.
func assertBidirectional(t *testing.T, listener daemontransport.Listener, dialCfg *thintransport.DialConfig) {
	t.Helper()

	acceptCh := make(chan net.Conn, 1)
	acceptErrCh := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			acceptErrCh <- err
			return
		}
		acceptCh <- c
	}()

	client, err := dialCfg.Dial()
	require.NoError(t, err)
	defer client.Close()

	var server net.Conn
	select {
	case server = <-acceptCh:
	case err := <-acceptErrCh:
		t.Fatalf("accept: %v", err)
	}
	defer server.Close()

	cToS := []byte("client-to-server")
	sToC := []byte("server-to-client")

	_, err = client.Write(cToS)
	require.NoError(t, err)
	buf := make([]byte, len(cToS))
	_, err = io.ReadFull(server, buf)
	require.NoError(t, err)
	require.Equal(t, cToS, buf)

	_, err = server.Write(sToC)
	require.NoError(t, err)
	buf2 := make([]byte, len(sToC))
	_, err = io.ReadFull(client, buf2)
	require.NoError(t, err)
	require.Equal(t, sToC, buf2)
}
