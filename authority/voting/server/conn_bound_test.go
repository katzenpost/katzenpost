// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
)

// fakeAddr is a trivial net.Addr for the instrumented test connection.
type fakeAddr struct{}

func (fakeAddr) Network() string { return "fake" }
func (fakeAddr) String() string  { return "fake" }

// blockingConn is a net.Conn whose LocalAddr blocks until release is closed,
// recording how many handlers are parked there at once. The listen worker reads
// RemoteAddr on the accept path for the connection limiter, before it spawns the
// handler, so the probe must sit in a method only the handler reaches: onConn
// reads LocalAddr immediately after RemoteAddr, and the worker holds a
// concurrency slot for the whole life of the handler, so the peak of active is
// the number of handlers run concurrently.
type blockingConn struct {
	active    *atomic.Int32
	maxActive *atomic.Int32
	release   chan struct{}
}

func (c *blockingConn) RemoteAddr() net.Addr { return fakeAddr{} }

func (c *blockingConn) LocalAddr() net.Addr {
	n := c.active.Add(1)
	for {
		m := c.maxActive.Load()
		if n <= m || c.maxActive.CompareAndSwap(m, n) {
			break
		}
	}
	<-c.release
	c.active.Add(-1)
	return fakeAddr{}
}
func (c *blockingConn) Read([]byte) (int, error)         { return 0, errors.New("closed") }
func (c *blockingConn) Write([]byte) (int, error)        { return 0, errors.New("closed") }
func (c *blockingConn) Close() error                     { return nil }
func (c *blockingConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingConn) SetWriteDeadline(time.Time) error { return nil }

// stubListener hands out a fixed number of connections, then blocks in Accept
// until closed so the listen worker parks rather than spinning.
type stubListener struct {
	conns     chan net.Conn
	done      chan struct{}
	closeOnce sync.Once
}

func (l *stubListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, &net.OpError{Op: "accept", Err: errors.New("listener closed")}
	}
}
func (l *stubListener) Close() error   { l.closeOnce.Do(func() { close(l.done) }); return nil }
func (l *stubListener) Addr() net.Addr { return fakeAddr{} }

// TestListenWorkerBoundsConcurrentConns floods listenWorker with more
// connections than the configured cap and asserts the number of handlers
// running at once never exceeds MaxConcurrentConns.
func TestListenWorkerBoundsConcurrentConns(t *testing.T) {
	const capConns = 2
	const flood = 5

	logBackend, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	s := &Server{
		cfg: &config.Config{
			Server: &config.Server{WireKEMScheme: "x25519"},
		},
		logBackend: logBackend,
		log:        logBackend.GetLogger("conn_bound_test"),
		haltedCh:   make(chan interface{}),
	}
	s.state = &state{s: s}
	s.connSem = make(chan struct{}, capConns)

	active := &atomic.Int32{}
	maxActive := &atomic.Int32{}
	release := make(chan struct{})

	ln := &stubListener{conns: make(chan net.Conn, flood), done: make(chan struct{})}
	for i := 0; i < flood; i++ {
		ln.conns <- &blockingConn{active: active, maxActive: maxActive, release: release}
	}

	s.Add(1)
	go s.listenWorker(ln)

	// Wait until the worker has as many handlers parked as the cap allows.
	require.Eventually(t, func() bool { return active.Load() == capConns },
		2*time.Second, 5*time.Millisecond, "cap handlers should start")

	// Give an unbounded worker time to spawn more than the cap.
	time.Sleep(200 * time.Millisecond)
	require.Equal(t, int32(capConns), maxActive.Load(),
		"listenWorker must not run more than MaxConcurrentConns handlers at once")

	// Release the parked handlers and shut the worker down.
	close(release)
	close(s.haltedCh)
	ln.Close()
	require.Eventually(t, func() bool { return active.Load() == 0 },
		2*time.Second, 5*time.Millisecond, "handlers should drain")
	s.WaitGroup.Wait()
}
