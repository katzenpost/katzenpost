// SPDX-FileCopyrightText: © 2026 Jacob Appelbaum
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

type acceptAuthenticator struct{}

func (acceptAuthenticator) IsPeerValid(*wire.PeerCredentials) bool { return true }

// TestServeAuthorityConnHandlesMultipleCommands proves the responder serves
// more than one command over a single handshaked connection, which is what
// lets persistent inter-authority connections avoid a handshake per command.
func TestServeAuthorityConnHandlesMultipleCommands(t *testing.T) {
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

	lb, err := log.New("", "DEBUG", false)
	require.NoError(err)
	s := &Server{
		cfg: &config.Config{Server: &config.Server{KeepaliveTimeoutSec: 120, ResponseTimeoutSec: 30}},
		log: lb.GetLogger("serve-test"),
	}
	st := &state{log: lb.GetLogger("state"), s: s}
	s.state = st

	go s.serveAuthorityConn(respConn, respS, "peer")

	epoch, _, _ := epochtime.Now()
	for i := 0; i < 3; i++ {
		require.NoError(cliS.SendCommand(ctx, &commands.GetConsensus{Epoch: epoch + 1, Cmds: cliS.GetCommands()}))
		resp, err := cliS.RecvCommand(ctx)
		require.NoError(err, "command %d", i)
		_, ok := resp.(*commands.Consensus)
		require.True(ok, "command %d: expected *Consensus, got %T", i, resp)
	}
}
