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

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// TestBackgroundFetchConsensusReusesCachedPeerConn proves the gap-fill consensus
// fetch travels over an already-cached persistent peer connection rather than
// dialing a second, independent connection to that peer. A live handshaked
// session is pre-populated in the peer-connection cache; the fetch must reach
// the responder over that session. Before the fix the fetch used its own client
// with an independent dialer and never touched the cache, so the command was
// dialed to the (unreachable) configured address instead and never arrived.
func TestBackgroundFetchConsensusReusesCachedPeerConn(t *testing.T) {
	require := require.New(t)
	const wireKEM = "Xwing"

	sender, senderID, senderLink := mkAuthState(t, "sender", wireKEM)
	sender.hasIPv4 = true
	sender.documents = map[uint64]*pki.Document{}
	sender.s.cfg.Server.PKISignatureScheme = "Ed25519"
	_ = senderID

	idScheme := signschemes.ByName("Ed25519")
	require.NotNil(idScheme)
	respIDPub, _, err := idScheme.GenerateKey()
	require.NoError(err)

	kemScheme := kemschemes.ByName(wireKEM)
	require.NotNil(kemScheme)

	// Build a live handshaked session pair to stand in for a cached persistent
	// peer connection.
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

	senderConn, respConn := net.Pipe()
	t.Cleanup(func() { _ = senderConn.Close() })
	t.Cleanup(func() { _ = respConn.Close() })

	ea := make(chan error, 1)
	go func() { ea <- respSess.Initialize(context.Background(), respConn) }()
	require.NoError(senderSess.Initialize(context.Background(), senderConn))
	require.NoError(<-ea)

	// Pre-populate the cache: this is the connection the fetch must reuse.
	pc := sender.peerConnFor("responder")
	pc.session = senderSess
	pc.conn = senderConn

	// The one configured peer whose IdentityPublicKey differs from ours. Its
	// address is intentionally unreachable, so any path that dials it (instead
	// of reusing the cached session) cannot deliver the command.
	sender.s.cfg.Authorities = []*config.Authority{{
		Identifier:        "responder",
		IdentityPublicKey: respIDPub,
		Addresses:         []string{"tcp://127.0.0.1:1"},
	}}

	received := make(chan struct{}, 1)
	go func() {
		for {
			cmd, err := respSess.RecvCommand(context.Background())
			if err != nil {
				return
			}
			if _, ok := cmd.(*commands.GetConsensus); ok {
				select {
				case received <- struct{}{}:
				default:
				}
				_ = respSess.SendCommand(context.Background(), &commands.Consensus{ErrorCode: commands.ConsensusNotFound})
			}
		}
	}()

	epoch, _, _ := epochtime.Now()
	sender.Lock()
	sender.backgroundFetchConsensus(epoch)
	sender.Unlock()

	select {
	case <-received:
	case <-time.After(10 * time.Second):
		t.Fatal("the gap-fill fetch did not reuse the cached peer connection")
	}
}
