// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/connlimit"
	"github.com/katzenpost/katzenpost/core/log"
)

func TestListenWorkerKeepsAcceptingWhileAPeerWaitsForASlot(t *testing.T) {
	logBackend, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	s := &Server{
		cfg: &config.Config{
			Server: &config.Server{WireKEMScheme: "x25519"},
		},
		logBackend: logBackend,
		log:        logBackend.GetLogger("accept_while_peer_waits_test"),
		haltedCh:   make(chan interface{}),
	}
	s.state = &state{s: s}
	s.connSem = make(chan struct{}, 1)
	s.connSem <- struct{}{}
	s.connLimiter = connlimit.New(1024, 1024, 64, 1024)
	s.peerSet = connlimit.NewPeerSet()
	s.peerSet.Rebuild([]string{"tcp://192.0.2.7:1"})

	active := &atomic.Int32{}
	release := make(chan struct{})
	ln := &stubListener{conns: make(chan net.Conn, 2), done: make(chan struct{})}
	ln.conns <- &addrConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.7"), Port: 5}, active: active, release: release}
	ln.conns <- &addrConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.7"), Port: 6}, active: active, release: release}

	s.Add(1)
	go s.listenWorker(ln)

	require.Eventually(t, func() bool { return len(ln.conns) == 0 },
		time.Second, 5*time.Millisecond,
		"the accept loop stopped accepting while a peer waited for a connection slot")

	<-s.connSem
	close(release)
	close(s.haltedCh)
	ln.Close()
	s.WaitGroup.Wait()
}
