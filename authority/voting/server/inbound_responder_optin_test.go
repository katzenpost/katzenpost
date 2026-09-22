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

// newResponderConn stands up a responder handler and a handshaked authority
// client session over an in-memory pipe, with the responder's persistent-conn
// setting controlled by persistent.
func newResponderConn(t *testing.T, persistent bool) *wire.Session {
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
			PersistentPeerConns: persistent,
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

	cliHash := hash.Sum256From(cliIDPub)
	st.authorizedAuthorities[cliHash] = true
	st.authorityLinkKeys[cliHash] = cliLinkPub

	srvConn, cliConn := net.Pipe()
	t.Cleanup(func() { cliConn.Close() })

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

	hsErr := make(chan error, 1)
	go func() { hsErr <- cliS.Initialize(context.Background(), cliConn) }()
	require.NoError(<-hsErr)

	return cliS
}

// getConsensusRoundTrip sends one GetConsensus and reads the reply.
func getConsensusRoundTrip(ctx context.Context, cliS *wire.Session) (commands.Command, error) {
	epoch, _, _ := epochtime.Now()
	if err := cliS.SendCommand(ctx, &commands.GetConsensus{Epoch: epoch + 1, Cmds: cliS.GetCommands()}); err != nil {
		return nil, err
	}
	return cliS.RecvCommand(ctx)
}

// With PersistentPeerConns off (the default), the responder serves exactly one
// command on an authority connection and then closes it: a second round trip on
// the same connection fails.
func TestInboundResponderServesOneCommandWhenNotPersistent(t *testing.T) {
	cliS := newResponderConn(t, false)
	ctx := context.Background()

	resp, err := getConsensusRoundTrip(ctx, cliS)
	require.NoError(t, err, "the first command must be served")
	_, ok := resp.(*commands.Consensus)
	require.True(t, ok, "expected *Consensus, got %T", resp)

	// The responder closed the connection after the single command, so a second
	// round trip must fail rather than receive another reply.
	done := make(chan error, 1)
	go func() {
		_, err := getConsensusRoundTrip(ctx, cliS)
		done <- err
	}()
	select {
	case err := <-done:
		require.Error(t, err, "a second command on a non-persistent connection must fail")
	case <-time.After(10 * time.Second):
		t.Fatal("second round trip neither failed nor returned; connection was not closed")
	}
}

// With PersistentPeerConns on, the responder serves multiple commands on one
// handshaked authority connection.
func TestInboundResponderServesManyCommandsWhenPersistent(t *testing.T) {
	cliS := newResponderConn(t, true)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		resp, err := getConsensusRoundTrip(ctx, cliS)
		require.NoError(t, err, "command %d must be served on the reused connection", i)
		_, ok := resp.(*commands.Consensus)
		require.True(t, ok, "command %d: expected *Consensus, got %T", i, resp)
	}
}
