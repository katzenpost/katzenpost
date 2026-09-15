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
	"github.com/katzenpost/hpqc/sign"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// perPeerHarness is a responder plus one authorized authority identity, so a
// test can dial several connections from the same peer identity against the
// same server (and thus the same per-peer slot counter).
type perPeerHarness struct {
	srv         *Server
	kemScheme   kem.Scheme
	idScheme    sign.Scheme
	cliLinkPriv kem.PrivateKey
	cliHash     [publicKeyHashSize]byte
}

func newPerPeerHarness(t *testing.T, maxConnsPerPeer int, persistent bool) *perPeerHarness {
	t.Helper()
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
	t.Cleanup(func() { _ = db.Close() })

	srv := &Server{
		cfg: &config.Config{Server: &config.Server{
			WireKEMScheme:       wireKEM,
			PKISignatureScheme:  pkiSig,
			HandshakeTimeoutSec: 10,
			ResponseTimeoutSec:  30,
			KeepaliveTimeoutSec: 120,
			MaxConnsPerPeer:     maxConnsPerPeer,
			PersistentPeerConns: persistent,
		}},
		identityPublicKey: respIDPub,
		linkKey:           respLinkPriv,
		log:               lb.GetLogger("resp"),
		logBackend:        lb,
		haltedCh:          make(chan interface{}),
		connSem:           make(chan struct{}, 64),
	}
	st := &state{
		log:                   lb.GetLogger("resp-state"),
		s:                     srv,
		db:                    db,
		authorizedAuthorities: map[[publicKeyHashSize]byte]bool{},
		authorityLinkKeys:     map[[publicKeyHashSize]byte]kem.PublicKey{},
	}
	srv.state = st

	cliHash := hash.Sum256From(cliIDPub)
	st.authorizedAuthorities[cliHash] = true
	st.authorityLinkKeys[cliHash] = cliLinkPub

	return &perPeerHarness{
		srv:         srv,
		kemScheme:   kemScheme,
		idScheme:    idScheme,
		cliLinkPriv: cliLinkPriv,
		cliHash:     cliHash,
	}
}

// dial opens one connection to the responder, completes the handshake as the
// harness's authority identity, and returns the client session.
func (h *perPeerHarness) dial(t *testing.T) *wire.Session {
	t.Helper()
	require := require.New(t)

	srvConn, cliConn := net.Pipe()
	t.Cleanup(func() { cliConn.Close() })
	h.srv.state.Go(func() { h.srv.handleConn(srvConn) })

	cliCfg := &wire.SessionConfig{
		KEMScheme:          h.kemScheme,
		PKISignatureScheme: h.idScheme,
		Authenticator:      acceptAuthenticator{},
		AdditionalData:     h.cliHash[:],
		AuthenticationKey:  h.cliLinkPriv,
		RandomReader:       rand.Reader,
	}
	cliS, err := wire.NewPKISession(cliCfg, true)
	require.NoError(err)

	hsErr := make(chan error, 1)
	go func() { hsErr <- cliS.Initialize(context.Background(), cliConn) }()
	require.NoError(<-hsErr)
	return cliS
}

func roundTrip(ctx context.Context, cliS *wire.Session) (commands.Command, error) {
	epoch, _, _ := epochtime.Now()
	if err := cliS.SendCommand(ctx, &commands.GetConsensus{Epoch: epoch + 1, Cmds: cliS.GetCommands()}); err != nil {
		return nil, err
	}
	return cliS.RecvCommand(ctx)
}

// More than MaxConnsPerPeer concurrent connections from one authenticated
// identity are rejected: the excess connection completes the handshake but its
// first command is not served, because the responder returned at the per-peer
// cap and closed the connection.
func TestAcceptPerPeerCapRejectsExcessConns(t *testing.T) {
	h := newPerPeerHarness(t, 2, true) // persistent so accepted conns stay parked
	ctx := context.Background()

	// Fill the two per-peer slots and confirm both are served and parked in the
	// serve loop, so their handlers still hold their slots.
	for i := 0; i < 2; i++ {
		cliS := h.dial(t)
		resp, err := roundTrip(ctx, cliS)
		require.NoError(t, err, "connection %d must be served", i)
		_, ok := resp.(*commands.Consensus)
		require.True(t, ok, "connection %d: expected *Consensus, got %T", i, resp)
	}

	// The third connection from the same identity handshakes but must be torn
	// down at the per-peer cap, so its first round trip fails.
	third := h.dial(t)
	done := make(chan error, 1)
	go func() {
		_, err := roundTrip(ctx, third)
		done <- err
	}()
	select {
	case err := <-done:
		require.Error(t, err, "a connection beyond MaxConnsPerPeer must be rejected")
	case <-time.After(10 * time.Second):
		t.Fatal("excess connection was neither served nor rejected")
	}
}

// A peer that completes the handshake and then stalls without sending a command
// is torn down at the short first-command deadline, well before the full
// ReadTimeout.
func TestAcceptFirstCommandDeadlineTearsDownStall(t *testing.T) {
	orig := firstCommandTimeout
	firstCommandTimeout = 300 * time.Millisecond
	defer func() { firstCommandTimeout = orig }()

	h := newPerPeerHarness(t, 8, false)
	cliS := h.dial(t)

	// Never send a command. The responder must close the connection at the
	// first-command deadline, which the client observes as a failed receive
	// arriving far sooner than the 30s ResponseTimeout.
	done := make(chan error, 1)
	go func() {
		_, err := cliS.RecvCommand(context.Background())
		done <- err
	}()

	start := time.Now()
	select {
	case err := <-done:
		require.Error(t, err, "a post-handshake stall must be torn down")
		require.Less(t, time.Since(start), 10*time.Second,
			"the stall must be torn down at the short first-command deadline, not the full ReadTimeout")
	case <-time.After(10 * time.Second):
		t.Fatal("stalled connection was not torn down at the first-command deadline")
	}
}
