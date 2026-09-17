// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
)

// TestShutdownClosesWedgedPeerConn proves shutdown does not stall on an outbound
// send wedged on a cached persistent peer connection. The send goroutine holds
// the peer lock across a write that never completes (the pipe peer never reads);
// it is counted in the server WaitGroup that halt() drains before state.Halt()
// closes cached peer connections. Shutdown must close those connections first so
// the wedged write is released and the drain completes promptly.
func TestShutdownClosesWedgedPeerConn(t *testing.T) {
	require := require.New(t)

	lb, err := log.New("", "DEBUG", false)
	require.NoError(err)

	db, err := bolt.Open(filepath.Join(t.TempDir(), "state.db"), 0600, nil)
	require.NoError(err)
	t.Cleanup(func() { _ = db.Close() })

	srv := &Server{
		cfg: &config.Config{Server: &config.Server{
			PersistentPeerConns: true,
			ResponseTimeoutSec:  30,
			KeepaliveTimeoutSec: 120,
		}},
		log:        lb.GetLogger("srv"),
		logBackend: lb,
		haltedCh:   make(chan interface{}),
	}
	st := &state{log: lb.GetLogger("state"), s: srv, db: db}
	srv.state = st

	senderConn, respConn := net.Pipe()
	t.Cleanup(func() { _ = senderConn.Close() })
	t.Cleanup(func() { _ = respConn.Close() })

	// A cached peer conn whose underlying connection is a pipe the peer never
	// reads from.
	pc := st.peerConnFor("peer")
	pc.conn = senderConn
	pc.setLive(senderConn)

	// Simulate an in-flight outbound send: hold the peer lock and block on a
	// write that never drains, counted in the server WaitGroup like a real send.
	holdingLock := make(chan struct{})
	srv.Add(1)
	go func() {
		defer srv.Done()
		pc.mu.Lock()
		defer pc.mu.Unlock()
		close(holdingLock)
		_, _ = senderConn.Write(make([]byte, 4096))
	}()
	<-holdingLock
	// Give the goroutine a moment to enter the blocking write.
	time.Sleep(100 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		srv.Shutdown()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Shutdown blocked on a wedged peer connection")
	}
}
