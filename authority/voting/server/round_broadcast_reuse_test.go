// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func runRoundBroadcasts(t *testing.T, persistent bool) int32 {
	t.Helper()
	require := require.New(t)
	const wireKEM = "Xwing"

	sender, senderID, _ := mkAuthState(t, "sender", wireKEM)
	responder, respID, respLink := mkAuthState(t, "responder", wireKEM)

	sender.s.cfg.Server.PersistentPeerConns = persistent
	sender.s.cfg.Server.PKISignatureScheme = "Ed25519"
	responder.s.cfg.Server.PKISignatureScheme = "Ed25519"

	sh := hash.Sum256From(senderID)
	rh := hash.Sum256From(respID)
	responder.authorizedAuthorities[sh] = true
	sender.authorizedAuthorities[rh] = true

	idScheme := signschemes.ByName("Ed25519")
	kemScheme := kemschemes.ByName(wireKEM)
	respCfg := &wire.SessionConfig{
		KEMScheme:          kemScheme,
		PKISignatureScheme: idScheme,
		Authenticator:      responder,
		AdditionalData:     rh[:],
		AuthenticationKey:  respLink,
		RandomReader:       rand.Reader,
	}

	var dials int32
	sender.dialContextFn = func(ctx context.Context, network, addr string) (net.Conn, error) {
		atomic.AddInt32(&dials, 1)
		cli, srvConn := net.Pipe()
		go func() {
			rs, err := wire.NewPKISession(respCfg, false)
			if err != nil {
				srvConn.Close()
				return
			}
			if err := rs.Initialize(context.Background(), srvConn); err != nil {
				srvConn.Close()
				return
			}
			responder.s.serveAuthorityConn(srvConn, rs, "sender", nil)
		}()
		return cli, nil
	}

	peer := &config.Authority{Identifier: "responder", Addresses: []string{"tcp://127.0.0.1:1"}}
	epoch, _, _ := epochtime.Now()

	round := []commands.Command{
		&commands.Vote{Epoch: epoch + 1, PublicKey: senderID, Payload: []byte("vote")},
		&commands.Reveal{Epoch: epoch + 1, PublicKey: senderID, Payload: []byte("reveal")},
		&commands.Cert{Epoch: epoch + 1, PublicKey: senderID, Payload: []byte("cert")},
		&commands.Sig{Epoch: epoch + 1, PublicKey: senderID, Payload: []byte("sig")},
	}
	for i, cmd := range round {
		resp, err := sender.doSendCommand(peer, cmd, peer.Addresses)
		require.NoError(err, "broadcast %d (%T)", i, cmd)
		require.NotNil(resp, "broadcast %d (%T): nil response", i, cmd)
	}

	sender.closeAllPeerConns()
	return atomic.LoadInt32(&dials)
}

func TestRoundBroadcastsReuseOneHandshake(t *testing.T) {
	dials := runRoundBroadcasts(t, true)
	require.Equal(t, int32(1), dials,
		"expected one handshake for the four per-round broadcasts")
}

func TestRoundBroadcastsStatelessFallback(t *testing.T) {
	dials := runRoundBroadcasts(t, false)
	require.Equal(t, int32(4), dials,
		"expected one handshake per broadcast with reuse disabled")
}
