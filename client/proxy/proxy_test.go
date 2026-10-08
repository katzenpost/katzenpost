// SPDX-License-Identifier: AGPL-3.0-only

package proxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type socksRequest struct {
	method   byte
	user     string
	password string
	target   string
}

func socks5Server(t *testing.T) (string, <-chan socksRequest) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	ch := make(chan socksRequest, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req socksRequest
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		methods := make([]byte, hdr[1])
		if _, err := io.ReadFull(conn, methods); err != nil {
			return
		}
		req.method = 0x00
		for _, m := range methods {
			if m == 0x02 {
				req.method = 0x02
			}
		}
		if _, err := conn.Write([]byte{0x05, req.method}); err != nil {
			return
		}
		if req.method == 0x02 {
			b := make([]byte, 2)
			if _, err := io.ReadFull(conn, b); err != nil {
				return
			}
			u := make([]byte, b[1])
			if _, err := io.ReadFull(conn, u); err != nil {
				return
			}
			pl := make([]byte, 1)
			if _, err := io.ReadFull(conn, pl); err != nil {
				return
			}
			p := make([]byte, pl[0])
			if _, err := io.ReadFull(conn, p); err != nil {
				return
			}
			req.user, req.password = string(u), string(p)
			if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
				return
			}
		}
		r := make([]byte, 4)
		if _, err := io.ReadFull(conn, r); err != nil {
			return
		}
		var host string
		switch r[3] {
		case 0x01:
			a := make([]byte, 4)
			if _, err := io.ReadFull(conn, a); err != nil {
				return
			}
			host = net.IP(a).String()
		case 0x03:
			l := make([]byte, 1)
			if _, err := io.ReadFull(conn, l); err != nil {
				return
			}
			a := make([]byte, l[0])
			if _, err := io.ReadFull(conn, a); err != nil {
				return
			}
			host = string(a)
		default:
			return
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(conn, port); err != nil {
			return
		}
		req.target = net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port))))
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})
		ch <- req
	}()
	return ln.Addr().String(), ch
}

func dialThrough(t *testing.T, cfg *Config) socksRequest {
	addr, ch := socks5Server(t)
	cfg.Network = netTCP
	cfg.Address = addr
	require.NoError(t, cfg.FixupAndValidate())
	var dial DialContextFn
	require.NotPanics(t, func() { dial = cfg.ToDialContext("session 1") })
	require.NotNil(t, dial)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dial(ctx, "tcp", "192.0.2.1:4242")
	require.NoError(t, err)
	conn.Close()
	select {
	case req := <-ch:
		return req
	case <-ctx.Done():
		t.Fatal("proxy saw no request")
	}
	return socksRequest{}
}

func TestSOCKS5WithoutAuth(t *testing.T) {
	req := dialThrough(t, &Config{Type: typeSocks5})
	require.Equal(t, byte(0x00), req.method)
	require.Equal(t, "192.0.2.1:4242", req.target)
}

func TestSOCKS5WithAuth(t *testing.T) {
	req := dialThrough(t, &Config{Type: typeSocks5, User: "alice", Password: "secret"})
	require.Equal(t, byte(0x02), req.method)
	require.Equal(t, "alice", req.user)
	require.Equal(t, "secret", req.password)
	require.Equal(t, "192.0.2.1:4242", req.target)
}

func TestTorSOCKS5Isolation(t *testing.T) {
	req := dialThrough(t, &Config{Type: typeTorSocks5})
	require.Equal(t, byte(0x02), req.method)
	require.Contains(t, req.user, torSocks5ProcessIsolation)
	require.Equal(t, "\x00", req.password)
	require.Equal(t, "192.0.2.1:4242", req.target)
}

func TestTorSOCKS5RejectsUser(t *testing.T) {
	cfg := &Config{Type: typeTorSocks5, Network: netTCP, Address: "127.0.0.1:9050", User: "a", Password: "b"}
	require.Error(t, cfg.FixupAndValidate())
}
