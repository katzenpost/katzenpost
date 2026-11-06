// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"context"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	signschemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/stretchr/testify/require"
)

type rebindingRelay struct {
	front  *net.UDPConn
	server *net.UDPAddr

	mu     sync.Mutex
	back   *net.UDPConn
	client *net.UDPAddr
}

func newRebindingRelay(t *testing.T, server net.Addr) *rebindingRelay {
	t.Helper()
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	r := &rebindingRelay{front: front, server: server.(*net.UDPAddr)}
	r.rebind(t)
	t.Cleanup(func() {
		front.Close()
		r.mu.Lock()
		r.back.Close()
		r.mu.Unlock()
	})
	go r.forwardToServer()
	return r
}

func (r *rebindingRelay) forwardToServer() {
	buf := make([]byte, 2048)
	for {
		n, from, err := r.front.ReadFromUDP(buf)
		if err != nil {
			return
		}
		r.mu.Lock()
		r.client = from
		back := r.back
		r.mu.Unlock()
		back.WriteToUDP(buf[:n], r.server)
	}
}

func (r *rebindingRelay) forwardToClient(back *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		n, err := back.Read(buf)
		if err != nil {
			return
		}
		r.mu.Lock()
		client := r.client
		r.mu.Unlock()
		if client != nil {
			r.front.WriteToUDP(buf[:n], client)
		}
	}
}

func (r *rebindingRelay) rebind(t *testing.T) net.Addr {
	t.Helper()
	back, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	go r.forwardToClient(back)
	r.mu.Lock()
	old := r.back
	r.back = back
	r.mu.Unlock()
	if old != nil {
		old.Close()
	}
	return back.LocalAddr()
}

func (r *rebindingRelay) backAddr() net.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.back.LocalAddr()
}

func exchange(t *testing.T, from, to net.Conn, b byte) {
	t.Helper()
	require.NoError(t, from.SetWriteDeadline(time.Now().Add(10*time.Second)))
	_, err := from.Write([]byte{b})
	require.NoError(t, err)
	require.NoError(t, to.SetReadDeadline(time.Now().Add(10*time.Second)))
	got := make([]byte, 1)
	_, err = io.ReadFull(to, got)
	require.NoError(t, err)
	require.Equal(t, b, got[0])
}

func roamingPair(t *testing.T, dialOpts *Options) (*QuicListener, *rebindingRelay, net.Conn, net.Conn) {
	t.Helper()
	_, identityPrivateKey, err := signschemes.ByName(testIdentityScheme).GenerateKey()
	require.NoError(t, err)
	key, err := LoadStaticKey(filepath.Join(t.TempDir(), "quic-tls.key"), nil)
	require.NoError(t, err)
	l, err := ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, key, nil)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	relay := newRebindingRelay(t, l.Addr())
	u, err := url.Parse("quic://" + relay.front.LocalAddr().String())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := DialURL(u, ctx, nil, key.Hash(), dialOpts)
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	_, err = client.Write([]byte{0})
	require.NoError(t, err)
	server, err := l.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { server.Close() })
	var first [1]byte
	_, err = io.ReadFull(server, first[:])
	require.NoError(t, err)
	exchange(t, server, client, 1)
	require.Equal(t, relay.backAddr().String(), server.RemoteAddr().String())
	return l, relay, client, server
}

func noSecondHandshake(t *testing.T, l *QuicListener) func() {
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			c.Close()
			accepted <- struct{}{}
		}
	}()
	return func() {
		select {
		case <-accepted:
			t.Fatal("roaming made the client handshake again")
		default:
		}
	}
}

func TestQUICLinkSurvivesTheClientRoaming(t *testing.T) {
	l, relay, client, server := roamingPair(t, nil)
	check := noSecondHandshake(t, l)
	for i := byte(2); i < 8; i += 2 {
		roamed := relay.rebind(t)
		exchange(t, client, server, i)
		exchange(t, server, client, i+1)
		require.Eventually(t, func() bool { return server.RemoteAddr().String() == roamed.String() }, 5*time.Second, 10*time.Millisecond, "the listener kept sending to the client's old address")
	}
	check()
}

func TestQUICListenerReachesARoamedClientAfterItsNextKeepalive(t *testing.T) {
	keepAlive, jitter := time.Second, 0.0
	l, relay, client, server := roamingPair(t, (&Options{KeepAlivePeriod: &keepAlive, KeepAliveJitter: &jitter}).ForClient())
	check := noSecondHandshake(t, l)
	roamed := relay.rebind(t)
	start := time.Now()
	exchange(t, server, client, 2)
	require.Less(t, time.Since(start), 5*time.Second)
	require.Eventually(t, func() bool { return server.RemoteAddr().String() == roamed.String() }, 5*time.Second, 10*time.Millisecond)
	exchange(t, client, server, 3)
	check()
}
