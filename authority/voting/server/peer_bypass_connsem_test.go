// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/connlimit"
	"github.com/katzenpost/katzenpost/core/log"
)

type addrConn struct {
	remote  net.Addr
	active  *atomic.Int32
	release chan struct{}
}

func (c *addrConn) RemoteAddr() net.Addr { return c.remote }

func (c *addrConn) LocalAddr() net.Addr {
	c.active.Add(1)
	<-c.release
	c.active.Add(-1)
	return fakeAddr{}
}

func (c *addrConn) Read([]byte) (int, error)         { return 0, errors.New("closed") }
func (c *addrConn) Write([]byte) (int, error)        { return 0, errors.New("closed") }
func (c *addrConn) Close() error                     { return nil }
func (c *addrConn) SetDeadline(time.Time) error      { return nil }
func (c *addrConn) SetReadDeadline(time.Time) error  { return nil }
func (c *addrConn) SetWriteDeadline(time.Time) error { return nil }

func TestListenWorkerReservesHeadroomForPeerAndLoopback(t *testing.T) {
	logBackend, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	s := &Server{
		cfg: &config.Config{
			Server: &config.Server{WireKEMScheme: "x25519"},
		},
		logBackend: logBackend,
		log:        logBackend.GetLogger("peer_reserve_test"),
		haltedCh:   make(chan interface{}),
	}
	s.state = &state{s: s}
	s.connSem = make(chan struct{}, 4)
	s.connReserve = 2
	s.connSem <- struct{}{}
	s.connSem <- struct{}{}
	s.connLimiter = connlimit.New(1024, 1024, 64, 1024)
	s.peerSet = connlimit.NewPeerSet()
	s.peerSet.Rebuild([]string{"tcp://192.0.2.7:1"})

	active := &atomic.Int32{}
	release := make(chan struct{})

	ln := &stubListener{conns: make(chan net.Conn, 2), done: make(chan struct{})}
	ln.conns <- &addrConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.7"), Port: 5}, active: active, release: release}
	ln.conns <- &addrConn{remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 6}, active: active, release: release}

	s.Add(1)
	go s.listenWorker(ln)

	require.Eventually(t, func() bool { return active.Load() == 2 },
		2*time.Second, 5*time.Millisecond,
		"peer and loopback handlers must run in the reserved headroom while clients hold every non-reserved slot")

	close(release)
	close(s.haltedCh)
	ln.Close()
	s.WaitGroup.Wait()
}
