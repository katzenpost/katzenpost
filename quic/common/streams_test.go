// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"context"
	"crypto/tls"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
)

func TestQuicSecondStreamIsRefused(t *testing.T) {
	const parked = 256 << 10
	ql, err := quic.ListenAddr("127.0.0.1:0", GenerateTLSConfig(), Config())
	require.NoError(t, err)
	l := &QuicListener{Listener: ql}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := quic.DialAddr(ctx, l.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}}, Config())
	require.NoError(t, err)
	defer c.CloseWithError(0, "")
	first, err := c.OpenStream()
	require.NoError(t, err)
	_, err = first.Write([]byte{0})
	require.NoError(t, err)
	server, err := l.Accept()
	require.NoError(t, err)
	defer server.Close()
	_, err = io.ReadFull(server, make([]byte, 1))
	require.NoError(t, err)

	second, err := c.OpenStream()
	if err != nil {
		return
	}
	if _, err = second.Write(make([]byte, parked)); err != nil {
		return
	}
	actx, acancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer acancel()
	pulled, err := server.(*QuicConn).Conn.AcceptStream(actx)
	if err != nil {
		return
	}
	pulled.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _ := io.ReadFull(pulled, make([]byte, parked))
	require.Less(t, n, parked, "a second stream on a one-stream link was accepted and the server buffered %d bytes from it", n)
}
