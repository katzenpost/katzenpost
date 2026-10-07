// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"container/list"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/connlimit"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/replica/config"
)

type remoteAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c *remoteAddrConn) RemoteAddr() net.Addr { return c.remote }

type chanListener struct {
	conns chan net.Conn
	done  chan struct{}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: net.ErrClosed}
	}
}

func (l *chanListener) Close() error { return nil }

func (l *chanListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func TestReplicaLogsCarryNoPeerAddress(t *testing.T) {
	p := filepath.Join(t.TempDir(), "replica.log")
	backend, err := log.New(p, "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	limiter := connlimit.New(1, 1, 0, 0)
	_, ok := limiter.TryAcquire(&net.TCPAddr{IP: net.ParseIP("10.0.0.9"), Port: 1}, false)
	require.True(t, ok)
	cl := &chanListener{conns: make(chan net.Conn, 1), done: make(chan struct{})}
	l := &Listener{
		server: &Server{
			cfg:         &config.Config{HandshakeTimeout: 5000},
			logBackend:  backend,
			connLimiter: limiter,
			peerSet:     connlimit.NewPeerSet(),
		},
		l:          cl,
		log:        backend.GetLogger("listener"),
		conns:      list.New(),
		closeAllCh: make(chan interface{}),
	}
	workerDone := make(chan struct{})
	go func() {
		l.worker()
		close(workerDone)
	}()
	refusedSrv, refusedCli := net.Pipe()
	cl.conns <- &remoteAddrConn{Conn: refusedSrv, remote: &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4242}}
	_, err = refusedCli.Read(make([]byte, 1))
	require.Error(t, err)
	close(cl.done)
	<-workerDone

	srv, cli := net.Pipe()
	defer cli.Close()
	c := newIncomingConn(l, &remoteAddrConn{Conn: srv, remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.44"), Port: 4243}}, nil, kemschemes.ByName("xwing"), signschemes.ByName("ed25519"))
	_, linkKey, err := kemschemes.ByName("xwing").GenerateKeyPair()
	require.NoError(t, err)
	session, err := wire.NewPKISession(&wire.SessionConfig{
		KEMScheme:          kemschemes.ByName("xwing"),
		PKISignatureScheme: signschemes.ByName("ed25519"),
		Authenticator:      c,
		AdditionalData:     make([]byte, 32),
		AuthenticationKey:  linkKey,
		RandomReader:       rand.Reader,
	}, false)
	require.NoError(t, err)
	go func() {
		_, _ = cli.Write(make([]byte, 4096))
		cli.Close()
	}()
	_, err = c.performHandshakeAndAuth(session)
	require.Error(t, err)

	b, err := os.ReadFile(p)
	require.NoError(t, err)
	logged := string(b)
	require.Contains(t, logged, "Refusing connection")
	require.Contains(t, logged, "New incoming connection")
	require.Contains(t, logged, "Handshake failed")
	for _, ip := range []string{"203.0.113.7", "192.0.2.44"} {
		require.NotContains(t, logged, ip)
	}
}
