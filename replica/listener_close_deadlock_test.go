// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"container/list"
	"net"
	"testing"
	"time"

	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/replica/config"
)

func newDeadlockTestListener(t *testing.T) *Listener {
	backend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	server := &Server{
		cfg:        &config.Config{},
		logBackend: backend,
	}
	return &Listener{
		server:     server,
		log:        backend.GetLogger("deadlock test listener"),
		conns:      list.New(),
		closeAllCh: make(chan interface{}),
	}
}

// TestIncomingConnCloseNoReceiver asserts that Close() cannot block the
// caller when the connection worker is not draining closeConnectionCh.
// This is the window CloseOldConns hits during a disconnect+reconnect
// race, where a blocking Close() under the listener lock wedges the
// listener permanently.
func TestIncomingConnCloseNoReceiver(t *testing.T) {
	l := newDeadlockTestListener(t)
	connRx, connTx := net.Pipe()
	defer connRx.Close()
	defer connTx.Close()

	wireScheme := kemschemes.ByName("x25519")
	pkiScheme := signschemes.ByName("ed25519")
	c := newIncomingConn(l, connRx, nil, wireScheme, pkiScheme)

	done := make(chan struct{})
	go func() {
		c.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close() blocked with no receiver draining closeConnectionCh")
	}
}

// TestCloseOldConnsNoReceiver drives a second connection from the same
// peer through CloseOldConns while the old conn has no receiver, then
// asserts the listener lock is still serviceable afterward.
func TestCloseOldConnsNoReceiver(t *testing.T) {
	l := newDeadlockTestListener(t)
	wireScheme := kemschemes.ByName("x25519")
	pkiScheme := signschemes.ByName("ed25519")

	linkpub, _, err := wireScheme.GenerateKeyPair()
	require.NoError(t, err)

	rx1, tx1 := net.Pipe()
	defer rx1.Close()
	defer tx1.Close()
	rx2, tx2 := net.Pipe()
	defer rx2.Close()
	defer tx2.Close()

	ad := make([]byte, 32)

	oldConn := newIncomingConn(l, rx1, nil, wireScheme, pkiScheme)
	oldConn.setSession(&MockSession{pk: linkpub, ad: ad})
	oldConn.e = l.conns.PushFront(oldConn)
	l.onInitializedConn(oldConn)

	newer := newIncomingConn(l, rx2, nil, wireScheme, pkiScheme)
	newer.setSession(&MockSession{pk: linkpub, ad: ad})
	newer.e = l.conns.PushFront(newer)
	l.onInitializedConn(newer)

	done := make(chan struct{})
	go func() {
		require.NoError(t, l.CloseOldConns(newer))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("CloseOldConns blocked on an old conn Close() with no receiver")
	}

	lockOK := make(chan struct{})
	go func() {
		_, err := l.GetConnIdentities()
		require.NoError(t, err)
		close(lockOK)
	}()
	select {
	case <-lockOK:
	case <-time.After(3 * time.Second):
		t.Fatal("listener lock wedged after CloseOldConns")
	}
}
