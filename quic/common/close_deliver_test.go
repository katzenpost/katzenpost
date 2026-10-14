// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestQuicCloseDeliversToAPeerThatFinishedSendingFirst(t *testing.T) {
	ql, err := quic.ListenAddr("127.0.0.1:0", GenerateTLSConfig(), Config())
	require.NoError(t, err)
	l := &QuicListener{Listener: ql}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, l.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{DefaultALPN}}, Config())
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStream()
	require.NoError(t, err)
	_, err = stream.Write([]byte{0})
	require.NoError(t, err)
	require.NoError(t, stream.Close())

	server, err := l.Accept()
	require.NoError(t, err)
	b := make([]byte, 2)
	n, err := io.ReadFull(server, b)
	require.Equal(t, 1, n)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	msg := bytes.Repeat([]byte{0x42}, 256<<10)
	_, err = server.Write(msg)
	require.NoError(t, err)
	require.NoError(t, server.Close())
	time.Sleep(300 * time.Millisecond)

	require.NoError(t, stream.SetReadDeadline(time.Now().Add(5*time.Second)))
	got, err := io.ReadAll(stream)
	require.NoError(t, err, "Close dropped the reply to a peer that had finished sending")
	require.Equal(t, msg, got)
}

func TestQuicCloseOutlastsASlowReader(t *testing.T) {
	l, client, server := quicPair(t)
	defer l.Close()
	defer client.Close()
	msg := bytes.Repeat([]byte{0x42}, 256<<10)
	_, err := server.Write(msg)
	require.NoError(t, err)
	require.NoError(t, server.Close())
	time.Sleep(3 * time.Second)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))
	got := make([]byte, len(msg))
	_, err = io.ReadFull(client, got)
	require.NoError(t, err, "Close cut a reader that took longer than 2 s")
	require.Equal(t, msg, got)
}

func TestQuicCloseLingerIsBoundedAfterThePeerFinishedSending(t *testing.T) {
	bound := closeLinger
	closeLinger = 500 * time.Millisecond
	t.Cleanup(func() { closeLinger = bound })
	ql, err := quic.ListenAddr("127.0.0.1:0", GenerateTLSConfig(), Config())
	require.NoError(t, err)
	l := &QuicListener{Listener: ql}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, l.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{DefaultALPN}}, Config())
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStream()
	require.NoError(t, err)
	_, err = stream.Write([]byte{0})
	require.NoError(t, err)
	require.NoError(t, stream.Close())
	server, err := l.Accept()
	require.NoError(t, err)
	_, err = io.ReadAll(server)
	require.NoError(t, err)
	require.NoError(t, server.Close())
	select {
	case <-server.(*QuicConn).Conn.Context().Done():
	case <-time.After(closeLinger + time.Second):
		t.Fatal("Close lingered past closeLinger behind a peer that never closed")
	}
}
