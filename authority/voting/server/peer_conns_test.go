// SPDX-FileCopyrightText: © 2026 Jacob Appelbaum
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func mkAuthState(t *testing.T, name, wireKEM string) (st *state, idPub sign.PublicKey, linkPriv kem.PrivateKey) {
	t.Helper()
	idScheme := signschemes.ByName("Ed25519")
	kemScheme := kemschemes.ByName(wireKEM)
	require.NotNil(t, idScheme)
	require.NotNil(t, kemScheme)
	idPub, _, err := idScheme.GenerateKey()
	require.NoError(t, err)
	_, linkPriv, err = kemScheme.GenerateKeyPair()
	require.NoError(t, err)
	lb, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	srv := &Server{
		cfg: &config.Config{Server: &config.Server{
			WireKEMScheme:       wireKEM,
			DialTimeoutSec:      5,
			HandshakeTimeoutSec: 5,
			ResponseTimeoutSec:  30,
			KeepaliveTimeoutSec: 120,
			PersistentPeerConns: true,
		}},
		identityPublicKey: idPub,
		linkKey:           linkPriv,
		log:               lb.GetLogger(name),
		logBackend:        lb,
	}
	st = &state{
		log:                   lb.GetLogger(name + "-state"),
		s:                     srv,
		authorizedAuthorities: map[[publicKeyHashSize]byte]bool{},
	}
	srv.state = st
	return st, idPub, linkPriv
}

// TestDoSendCommandReusesConnection proves the sender reuses one handshaked
// session across commands: two sends to the same peer dial (and handshake)
// exactly once.
func TestDoSendCommandReusesConnection(t *testing.T) {
	require := require.New(t)
	const wireKEM = "Xwing"

	sender, senderID, _ := mkAuthState(t, "sender", wireKEM)
	responder, respID, respLink := mkAuthState(t, "responder", wireKEM)

	// Authorize each other.
	sh := hash.Sum256From(senderID)
	rh := hash.Sum256From(respID)
	responder.authorizedAuthorities[sh] = true
	sender.authorizedAuthorities[rh] = true

	kemScheme := kemschemes.ByName(wireKEM)
	respCfg := &wire.SessionConfig{
		KEMScheme:         kemScheme,
		Authenticator:     responder,
		AdditionalData:    rh[:],
		AuthenticationKey: respLink,
		RandomReader:      rand.Reader,
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

	for i := 0; i < 3; i++ {
		resp, err := sender.doSendCommand(peer, &commands.GetConsensus{Epoch: epoch + 1, Cmds: commands.NewPKICommands(nil)}, peer.Addresses)
		require.NoError(err, "send %d", i)
		_, ok := resp.(*commands.Consensus)
		require.True(ok, "send %d: expected *Consensus, got %T", i, resp)
	}
	require.Equal(int32(1), atomic.LoadInt32(&dials), "expected exactly one handshake for three commands")

	sender.closeAllPeerConns()
}
