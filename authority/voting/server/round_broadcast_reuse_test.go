// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func sendFourPhaseRound(t *testing.T, sender *state, peer *config.Authority, senderID sign.PublicKey) {
	t.Helper()
	require := require.New(t)
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
}

func TestRoundBroadcastsReuseOneHandshake(t *testing.T) {
	const wireKEM = "Xwing"
	sender, senderID, _ := mkAuthState(t, "sender", wireKEM)
	responder, respID, respLink := mkAuthState(t, "responder", wireKEM)

	sender.s.cfg.Server.PersistentPeerConns = true
	sender.s.cfg.Server.PKISignatureScheme = "Ed25519"
	responder.s.cfg.Server.PKISignatureScheme = "Ed25519"

	dials := installPeerResponder(t, sender, responder, senderID, respID, respLink, wireKEM)
	peer := &config.Authority{Identifier: "responder", Addresses: []string{"tcp://127.0.0.1:1"}}

	sendFourPhaseRound(t, sender, peer, senderID)
	sender.closeAllPeerConns()

	require.Equal(t, int32(1), atomic.LoadInt32(dials),
		"expected one handshake for the four per-round broadcasts")
}

func TestRoundBroadcastsStatelessFallback(t *testing.T) {
	const wireKEM = "Xwing"
	sender, senderID, _ := mkAuthState(t, "sender", wireKEM)
	responder, respID, respLink := mkAuthState(t, "responder", wireKEM)

	sender.s.cfg.Server.PersistentPeerConns = false
	sender.s.cfg.Server.PKISignatureScheme = "Ed25519"
	responder.s.cfg.Server.PKISignatureScheme = "Ed25519"

	dials := installPeerResponder(t, sender, responder, senderID, respID, respLink, wireKEM)
	peer := &config.Authority{Identifier: "responder", Addresses: []string{"tcp://127.0.0.1:1"}}

	sendFourPhaseRound(t, sender, peer, senderID)
	sender.closeAllPeerConns()

	require.Equal(t, int32(4), atomic.LoadInt32(dials),
		"expected one handshake per broadcast with reuse disabled")
}
