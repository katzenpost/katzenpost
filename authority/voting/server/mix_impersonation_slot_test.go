// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/katzenpost/hpqc/hash"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func TestMixIdentityNotBoundToLinkKey(t *testing.T) {
	require := require.New(t)

	orig := firstCommandTimeout
	firstCommandTimeout = 3 * time.Second

	var (
		connsMu sync.Mutex
		conns   []net.Conn
		wg      sync.WaitGroup
	)
	defer func() {
		connsMu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		connsMu.Unlock()
		wg.Wait()
		firstCommandTimeout = orig
	}()

	const (
		wireKEM = "Xwing"
		perPeer = 2
	)
	pkiSig := testSchemeName
	idScheme := signschemes.ByName(pkiSig)
	kemScheme := kemschemes.ByName(wireKEM)

	respIDPub, _, err := idScheme.GenerateKey()
	require.NoError(err)
	_, respLinkPriv, err := kemScheme.GenerateKeyPair()
	require.NoError(err)

	mixIDPub, _, err := idScheme.GenerateKey()
	require.NoError(err)
	mixHash := hash.Sum256From(mixIDPub)

	lb, err := log.New("", "ERROR", false)
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
			MaxConnsPerPeer:     perPeer,
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
		authorizedMixes:       map[[publicKeyHashSize]byte]string{mixHash: "victim-mix"},
	}
	srv.state = st

	dialAs := func(claim [publicKeyHashSize]byte) (*wire.Session, error) {
		_, linkPriv, err := kemScheme.GenerateKeyPair()
		require.NoError(err)
		srvConn, cliConn := net.Pipe()
		connsMu.Lock()
		conns = append(conns, srvConn, cliConn)
		connsMu.Unlock()
		wg.Add(1)
		srv.state.Go(func() {
			defer wg.Done()
			srv.handleConn(srvConn)
		})
		cliS, err := wire.NewPKISession(&wire.SessionConfig{
			KEMScheme:          kemScheme,
			PKISignatureScheme: idScheme,
			Authenticator:      acceptAuthenticator{},
			AdditionalData:     claim[:],
			AuthenticationKey:  linkPriv,
			RandomReader:       rand.Reader,
		}, true)
		require.NoError(err)
		hsErr := make(chan error, 1)
		go func() { hsErr <- cliS.Initialize(context.Background(), cliConn) }()
		select {
		case err := <-hsErr:
			return cliS, err
		case <-time.After(10 * time.Second):
			t.Fatal("handshake hung")
		}
		return nil, nil
	}

	_, attackerLink, err := kemScheme.GenerateKeyPair()
	require.NoError(err)
	auth := &wireAuthenticator{s: srv}
	ok := auth.IsPeerValid(&wire.PeerCredentials{AdditionalData: mixHash[:], PublicKey: attackerLink.Public()})
	require.True(ok)

	for i := 0; i < perPeer; i++ {
		_, err := dialAs(mixHash)
		if err != nil {
			return
		}
	}
	victim, err := dialAs(mixHash)
	require.NoError(err)
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := victim.SendCommand(ctx, &commands.GetConsensus{Epoch: 1, Cmds: victim.GetCommands()}); err != nil {
			done <- err
			return
		}
		_, err := victim.RecvCommand(ctx)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("legitimate mix refused while an anonymous attacker holds its per-peer slots: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("victim round trip hung")
	}
}
