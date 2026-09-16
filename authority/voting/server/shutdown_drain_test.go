// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// TestShutdownClosesIdleAuthorityConn proves shutdown does not hang on an
// authority peer that keeps a handshaked connection open and idle. The
// responder serves an authority connection in a loop bounded only by the long
// idle timeout and does not watch the halt signal, so shutdown must close
// accepted connections for the blocked handler to return.
func TestShutdownClosesIdleAuthorityConn(t *testing.T) {
	require := require.New(t)
	const (
		wireKEM = "Xwing"
		pkiSig  = "Ed25519"
	)

	idScheme := signschemes.ByName(pkiSig)
	kemScheme := kemschemes.ByName(wireKEM)
	require.NotNil(idScheme)
	require.NotNil(kemScheme)

	respIDPub, _, err := idScheme.GenerateKey()
	require.NoError(err)
	_, respLinkPriv, err := kemScheme.GenerateKeyPair()
	require.NoError(err)

	cliIDPub, _, err := idScheme.GenerateKey()
	require.NoError(err)
	cliLinkPub, cliLinkPriv, err := kemScheme.GenerateKeyPair()
	require.NoError(err)

	lb, err := log.New("", "DEBUG", false)
	require.NoError(err)

	db, err := bolt.Open(filepath.Join(t.TempDir(), "state.db"), 0600, nil)
	require.NoError(err)

	srv := &Server{
		cfg: &config.Config{Server: &config.Server{
			WireKEMScheme:       wireKEM,
			PKISignatureScheme:  pkiSig,
			HandshakeTimeoutSec: 10,
			ResponseTimeoutSec:  30,
			// Long idle timeout: this is what shutdown must not wait out.
			KeepaliveTimeoutSec: 120,
			// Persistent conns keep the responder in the multi-command serve
			// loop after the first command, which is the blocked handler this
			// test drains at shutdown.
			PersistentPeerConns: true,
		}},
		identityPublicKey: respIDPub,
		linkKey:           respLinkPriv,
		log:               lb.GetLogger("resp"),
		logBackend:        lb,
		haltedCh:          make(chan interface{}),
		connSem:           make(chan struct{}, 8),
	}
	st := &state{
		log:                   lb.GetLogger("resp-state"),
		s:                     srv,
		db:                    db,
		authorizedAuthorities: map[[publicKeyHashSize]byte]bool{},
		authorityLinkKeys:     map[[publicKeyHashSize]byte]kem.PublicKey{},
	}
	srv.state = st

	// Authorize the peer authority so the responder handshake classifies it as
	// an authority and enters the multi-command serve loop.
	cliHash := hash.Sum256From(cliIDPub)
	st.authorizedAuthorities[cliHash] = true
	st.authorityLinkKeys[cliHash] = cliLinkPub

	srvConn, cliConn := net.Pipe()

	// Run the responder handler the way an accepting listenWorker does.
	srv.state.Go(func() { srv.handleConn(srvConn) })

	cliCfg := &wire.SessionConfig{
		KEMScheme:          kemScheme,
		PKISignatureScheme: idScheme,
		Authenticator:      acceptAuthenticator{},
		AdditionalData:     cliHash[:],
		AuthenticationKey:  cliLinkPriv,
		RandomReader:       rand.Reader,
	}
	cliS, err := wire.NewPKISession(cliCfg, true)
	require.NoError(err)

	ctx := context.Background()
	hsErr := make(chan error, 1)
	go func() { hsErr <- cliS.Initialize(ctx, cliConn) }()
	require.NoError(<-hsErr)

	// Send one command and read its reply. This confirms the responder finished
	// the single-command path and is now blocked in the authority serve loop
	// waiting for more commands on this idle connection.
	epoch, _, _ := epochtime.Now()
	require.NoError(cliS.SendCommand(ctx, &commands.GetConsensus{Epoch: epoch + 1, Cmds: cliS.GetCommands()}))
	resp, err := cliS.RecvCommand(ctx)
	require.NoError(err)
	_, ok := resp.(*commands.Consensus)
	require.True(ok, "expected *Consensus, got %T", resp)

	// The peer now holds the connection open and idle. Shutdown must return
	// promptly instead of waiting out the 120s idle timeout on the handler.
	done := make(chan struct{})
	go func() {
		srv.Shutdown()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Shutdown blocked on an idle authority connection")
	}

	cliConn.Close()
}
