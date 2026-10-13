// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func quicPair(t *testing.T) (*QuicListener, net.Conn, net.Conn) {
	t.Helper()
	ql, err := quic.ListenAddr("127.0.0.1:0", GenerateTLSConfig(), Config())
	require.NoError(t, err)
	l := &QuicListener{Listener: ql}
	u, err := url.Parse("quic://" + l.Addr().String())
	require.NoError(t, err)
	client, err := DialURL(u, context.Background(), nil)
	require.NoError(t, err)
	_, err = client.Write([]byte{0})
	require.NoError(t, err)
	server, err := l.Accept()
	require.NoError(t, err)
	var b [1]byte
	_, err = io.ReadFull(server, b[:])
	require.NoError(t, err)
	return l, client, server
}

func TestQuicCloseDeliversLastWrite(t *testing.T) {
	l, client, server := quicPair(t)
	defer l.Close()
	defer client.Close()
	msg := bytes.Repeat([]byte{0x42}, 64<<10)
	_, err := server.Write(msg)
	require.NoError(t, err)
	require.NoError(t, server.Close())
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))
	got := make([]byte, len(msg))
	_, err = io.ReadFull(client, got)
	require.NoError(t, err)
	require.Equal(t, msg, got)
	_, err = client.Read(got[:1])
	require.ErrorIs(t, err, io.EOF)
}
