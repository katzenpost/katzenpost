// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/wire"
)

// armablePanicConn delegates to an underlying conn but panics on Write once
// armed, so a session's SendCommand can be made to panic after its handshake
// has already completed.
type armablePanicConn struct {
	net.Conn
	armed atomic.Bool
}

func (c *armablePanicConn) Write(b []byte) (int, error) {
	if c.armed.Load() {
		panic("boom in keepalive write")
	}
	return c.Conn.Write(b)
}

// TestSendPeerKeepalivesRecoversFromPanic proves a panic while sending a
// keepalive NoOp does not crash the authority. sendPeerKeepalives drives a
// cached session's SendCommand directly; unlike doSendCommand it had no panic
// recovery, so a panic in the send would unwind through the keepalive worker
// and take down the whole daemon.
func TestSendPeerKeepalivesRecoversFromPanic(t *testing.T) {
	require := require.New(t)
	const wireKEM = "Xwing"

	st, _, senderLink := mkAuthState(t, "sender", wireKEM)

	idScheme := signschemes.ByName("Ed25519")
	require.NotNil(idScheme)
	kemScheme := kemschemes.ByName(wireKEM)
	require.NotNil(kemScheme)

	senderCfg := &wire.SessionConfig{
		KEMScheme: kemScheme, PKISignatureScheme: idScheme,
		Authenticator: acceptAuthenticator{}, AdditionalData: []byte("sender"),
		AuthenticationKey: senderLink, RandomReader: rand.Reader,
	}
	_, respLink, err := kemScheme.GenerateKeyPair()
	require.NoError(err)
	respCfg := &wire.SessionConfig{
		KEMScheme: kemScheme, PKISignatureScheme: idScheme,
		Authenticator: acceptAuthenticator{}, AdditionalData: []byte("responder"),
		AuthenticationKey: respLink, RandomReader: rand.Reader,
	}
	senderSess, err := wire.NewPKISession(senderCfg, true)
	require.NoError(err)
	respSess, err := wire.NewPKISession(respCfg, false)
	require.NoError(err)

	rawSender, respConn := net.Pipe()
	t.Cleanup(func() { _ = rawSender.Close() })
	t.Cleanup(func() { _ = respConn.Close() })
	wrapped := &armablePanicConn{Conn: rawSender}

	// Run the responder handshake; the armed keepalive write panics before any
	// reply is needed, so no post-handshake reader is required.
	ea := make(chan error, 1)
	go func() { ea <- respSess.Initialize(context.Background(), respConn) }()
	require.NoError(senderSess.Initialize(context.Background(), wrapped))
	require.NoError(<-ea)

	// Arm the panic only now that the handshake is done.
	wrapped.armed.Store(true)

	pc := st.peerConnFor("peer")
	pc.session = senderSess
	pc.conn = wrapped

	require.NotPanics(func() { st.sendPeerKeepalives() },
		"a panic while sending a keepalive must be recovered, not crash the daemon")
}
