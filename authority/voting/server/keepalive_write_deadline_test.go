// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/wire"
)

// A keepalive NoOp to a peer whose connection has stalled must fail at the
// short keepalive write deadline and release pc.mu, rather than holding the
// session for the full ResponseTimeout and delaying a real send queued behind
// it. The peer's session is torn down when the bounded write fails.
func TestSendPeerKeepalivesBoundsStalledWrite(t *testing.T) {
	require := require.New(t)

	kemScheme := kemschemes.ByName("Xwing")
	require.NotNil(kemScheme)
	sigScheme := signschemes.ByName("Ed25519")
	require.NotNil(sigScheme)

	_, respPriv, err := kemScheme.GenerateKeyPair()
	require.NoError(err)
	_, cliPriv, err := kemScheme.GenerateKeyPair()
	require.NoError(err)

	respCfg := &wire.SessionConfig{
		KEMScheme: kemScheme, PKISignatureScheme: sigScheme,
		Authenticator: acceptAuthenticator{}, AdditionalData: []byte("resp"),
		AuthenticationKey: respPriv, RandomReader: rand.Reader,
	}
	cliCfg := &wire.SessionConfig{
		KEMScheme: kemScheme, PKISignatureScheme: sigScheme,
		Authenticator: acceptAuthenticator{}, AdditionalData: []byte("cli"),
		AuthenticationKey: cliPriv, RandomReader: rand.Reader,
	}
	respS, err := wire.NewPKISession(respCfg, false)
	require.NoError(err)
	cliS, err := wire.NewPKISession(cliCfg, true)
	require.NoError(err)

	respConn, cliConn := net.Pipe()
	defer respConn.Close()
	defer cliConn.Close()

	ctx := context.Background()
	ea := make(chan error, 1)
	go func() { ea <- respS.Initialize(ctx, respConn) }()
	require.NoError(cliS.Initialize(ctx, cliConn))
	require.NoError(<-ea)

	// The responder never reads again, so any keepalive write on the client
	// session blocks on the synchronous pipe until its deadline fires.
	orig := peerKeepaliveWriteTimeout
	peerKeepaliveWriteTimeout = 150 * time.Millisecond
	defer func() { peerKeepaliveWriteTimeout = orig }()

	st := &state{
		peerConns: map[string]*peerConn{
			"peer": {session: cliS, conn: cliConn},
		},
	}

	start := time.Now()
	st.sendPeerKeepalives()
	elapsed := time.Since(start)

	require.Less(elapsed, 3*time.Second,
		"a stalled keepalive write must be bounded by the short deadline, not the full ResponseTimeout")

	pc := st.peerConns["peer"]
	pc.mu.Lock()
	require.Nil(pc.session, "a keepalive whose bounded write timed out must close the stalled session")
	pc.mu.Unlock()
}
