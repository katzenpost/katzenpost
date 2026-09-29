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
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// TestServeAuthorityConnIdleWaitUsesKeepaliveTimeout proves the persistent
// authority serve loop waits out the long keepalive/idle timeout between
// commands rather than the short per-response timeout. The inbound session is
// built with ReadTimeout=ResponseTimeoutSec (1s here); RecvCommand's armIO caps
// any read deadline at that value, so before the fix an idle gap longer than
// ResponseTimeoutSec but shorter than KeepaliveTimeoutSec closes the connection
// and a second command never gets served.
func TestServeAuthorityConnIdleWaitUsesKeepaliveTimeout(t *testing.T) {
	require := require.New(t)

	kemScheme := kemschemes.ByName("Xwing")
	require.NotNil(kemScheme)
	sigScheme := signschemes.ByName("Ed25519")
	require.NotNil(sigScheme)

	_, respPriv, err := kemScheme.GenerateKeyPair()
	require.NoError(err)
	_, cliPriv, err := kemScheme.GenerateKeyPair()
	require.NoError(err)

	const responseTimeout = 1 * time.Second
	respCfg := &wire.SessionConfig{
		KEMScheme: kemScheme, PKISignatureScheme: sigScheme,
		Authenticator: acceptAuthenticator{}, AdditionalData: []byte("resp"),
		AuthenticationKey: respPriv, RandomReader: rand.Reader,
		// Mirror the real inbound session: read/write deadlines are the
		// per-response timeout, and the serve loop must not let that bound the
		// idle wait between commands.
		ReadTimeout:  responseTimeout,
		WriteTimeout: responseTimeout,
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
		cfg: &config.Config{Server: &config.Server{
			KeepaliveTimeoutSec: 5,
			ResponseTimeoutSec:  1,
		}},
		log: lb.GetLogger("serve-test"),
	}
	st := &state{log: lb.GetLogger("state"), s: s}
	s.state = st

	go s.serveAuthorityConn(respConn, respS, "peer", nil)

	epoch, _, _ := epochtime.Now()

	// First command right away.
	require.NoError(cliS.SendCommand(ctx, &commands.GetConsensus{Epoch: epoch + 1, Cmds: cliS.GetCommands()}))
	resp, err := cliS.RecvCommand(ctx)
	require.NoError(err)
	_, ok := resp.(*commands.Consensus)
	require.True(ok, "first command: expected *Consensus, got %T", resp)

	// Idle longer than ResponseTimeoutSec (1s) but well under KeepaliveTimeoutSec
	// (5s). The persistent connection must stay open across this gap.
	time.Sleep(2 * time.Second)

	require.NoError(cliS.SendCommand(ctx, &commands.GetConsensus{Epoch: epoch + 1, Cmds: cliS.GetCommands()}))
	resp, err = cliS.RecvCommand(ctx)
	require.NoError(err, "second command after idle gap: connection was closed by the short per-response timeout")
	_, ok = resp.(*commands.Consensus)
	require.True(ok, "second command: expected *Consensus, got %T", resp)
}
