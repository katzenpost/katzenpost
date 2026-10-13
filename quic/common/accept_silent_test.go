// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestQuicAcceptNotBlockedBySilentPeer(t *testing.T) {
	ql, err := quic.ListenAddr("127.0.0.1:0", GenerateTLSConfig(), Config())
	require.NoError(t, err)
	l := &QuicListener{Listener: ql}
	defer l.Close()

	silent, err := quic.DialAddr(context.Background(), l.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{DefaultALPN}}, Config())
	require.NoError(t, err)
	defer silent.CloseWithError(0, "")
	time.Sleep(100 * time.Millisecond)

	u, err := url.Parse("quic://" + l.Addr().String())
	require.NoError(t, err)
	good, err := DialURL(u, context.Background(), nil, nil, nil)
	require.NoError(t, err)
	defer good.Close()
	_, err = good.Write([]byte{1})
	require.NoError(t, err)

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(5 * time.Second):
		t.Fatalf("Accept still blocked after 5s behind a peer that opened no stream (AcceptStreamTimeout=%v)", AcceptStreamTimeout)
	}
}

func TestQuicSilentHandshakesDoNotLockOutPeers(t *testing.T) {
	ql, err := quic.ListenAddr("127.0.0.1:0", GenerateTLSConfig(), Config())
	require.NoError(t, err)
	l := &QuicListener{Listener: ql}
	defer l.Close()
	accepted := make(chan net.Conn, 64)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	for range 33 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, err := quic.DialAddr(ctx, l.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{DefaultALPN}}, Config())
		cancel()
		require.NoError(t, err)
		<-c.HandshakeComplete()
		defer c.CloseWithError(0, "")
	}
	u, err := url.Parse("quic://" + l.Addr().String())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	peer, err := DialURL(u, ctx, nil, nil, nil)
	require.NoError(t, err)
	defer peer.Close()
	_, err = peer.Write([]byte{1})
	require.NoError(t, err)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case c := <-accepted:
			defer c.Close()
			if c.RemoteAddr().(*net.UDPAddr).Port != peer.LocalAddr().(*net.UDPAddr).Port {
				continue
			}
			var b [1]byte
			_, err := io.ReadFull(c, b[:])
			require.NoError(t, err)
			return
		case <-deadline:
			var b [1]byte
			peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			_, readErr := peer.Read(b[:])
			t.Fatalf("peer not accepted within 5s behind 33 silent handshakes; peer read: %v", readErr)
		}
	}
}
