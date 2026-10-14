// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func acceptSilentPeer(t *testing.T) (net.Conn, *quic.Conn) {
	t.Helper()
	ql, err := quic.ListenAddr("127.0.0.1:0", GenerateTLSConfig(), Config())
	require.NoError(t, err)
	l := &QuicListener{Listener: ql}
	t.Cleanup(func() { l.Close() })
	silent, err := quic.DialAddr(context.Background(), l.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{DefaultALPN}}, Config())
	require.NoError(t, err)
	t.Cleanup(func() { silent.CloseWithError(0, "") })
	server, err := l.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { server.Close() })
	return server, silent
}

func TestQuicStreamWaitHonoursADeadlineSetBeforeRead(t *testing.T) {
	server, _ := acceptSilentPeer(t)
	require.NoError(t, server.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	start := time.Now()
	_, err := server.Read(make([]byte, 1))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Less(t, time.Since(start), time.Second)
}

func TestQuicStreamWaitHonoursADeadlineSetDuringRead(t *testing.T) {
	server, _ := acceptSilentPeer(t)
	readErr := make(chan error, 1)
	go func() {
		_, err := server.Read(make([]byte, 1))
		readErr <- err
	}()
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, server.SetReadDeadline(time.Now()))
	select {
	case err := <-readErr:
		var ne net.Error
		require.True(t, errors.As(err, &ne) && ne.Timeout(), "read returned %v", err)
	case <-time.After(time.Second):
		t.Fatal("a deadline set during the wait for the stream did not end the Read")
	}
}

func TestQuicCloseBeforeTheStreamClosesTheConnection(t *testing.T) {
	server, silent := acceptSilentPeer(t)
	readErr := make(chan error, 1)
	go func() {
		_, err := server.Read(make([]byte, 1))
		readErr <- err
	}()
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, server.Close())
	select {
	case err := <-readErr:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(time.Second):
		t.Fatal("Close did not end the wait for the stream")
	}
	select {
	case <-silent.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("Close before the stream left the connection open")
	}
}

func TestQuicConnWithoutAStreamDiesAtAcceptStreamTimeout(t *testing.T) {
	saved := AcceptStreamTimeout
	AcceptStreamTimeout = 200 * time.Millisecond
	t.Cleanup(func() { AcceptStreamTimeout = saved })
	_, silent := acceptSilentPeer(t)
	select {
	case <-silent.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("a connection that never opened a stream outlived AcceptStreamTimeout")
	}
}
