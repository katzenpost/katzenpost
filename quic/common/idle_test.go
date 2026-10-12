// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"context"
	"io"
	"net/url"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestQuicIdleLinkSurvivesPeerIdleTimeout(t *testing.T) {
	const peerIdle = 5 * time.Second
	ql, err := quic.ListenAddr("127.0.0.1:0", GenerateTLSConfig(), &quic.Config{MaxIdleTimeout: peerIdle})
	require.NoError(t, err)
	l := &QuicListener{Listener: ql}
	defer l.Close()

	u, err := url.Parse("quic://" + l.Addr().String())
	require.NoError(t, err)
	client, err := DialURL(u, context.Background(), nil)
	require.NoError(t, err)
	defer client.Close()
	_, err = client.Write([]byte{0})
	require.NoError(t, err)
	server, err := l.Accept()
	require.NoError(t, err)
	defer server.Close()

	var b [1]byte
	_, err = io.ReadFull(server, b[:])
	require.NoError(t, err)

	readErr := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(server, b[:])
		readErr <- err
	}()
	select {
	case err := <-readErr:
		t.Fatalf("idle link died: %v", err)
	case <-time.After(2 * peerIdle):
	}
	_, err = client.Write([]byte{9})
	require.NoError(t, err)
	require.NoError(t, <-readErr)
	require.Equal(t, byte(9), b[0])
}
