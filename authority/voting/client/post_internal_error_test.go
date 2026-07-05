// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

type internalErrorAuthority struct {
	linkKey kem.PrivateKey
	idKey   sign.PublicKey
	posts   atomic.Int32
}

func (a *internalErrorAuthority) IsPeerValid(*wire.PeerCredentials) bool {
	return true
}

func (a *internalErrorAuthority) serve(c net.Conn, g *geo.Geometry) {
	defer c.Close()
	id := hash.Sum256From(a.idKey)
	s, err := wire.NewPKISession(&wire.SessionConfig{
		KEMScheme:         testingScheme,
		Geometry:          g,
		Authenticator:     a,
		AdditionalData:    id[:],
		AuthenticationKey: a.linkKey,
		RandomReader:      rand.Reader,
	}, false)
	if err != nil {
		return
	}
	defer s.Close()
	if s.Initialize(context.Background(), c) != nil {
		return
	}
	if _, err := s.RecvCommand(context.Background()); err != nil {
		return
	}
	a.posts.Add(1)
	s.SendCommand(context.Background(), &commands.PostReplicaDescriptorStatus{ErrorCode: 4})
}

func TestPostInternalErrorIsRetried(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "client.log")
	logBackend, err := log.New(logPath, "DEBUG", false)
	require.NoError(t, err)
	defer logBackend.Close()
	g := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5)

	auths := make(map[string]*internalErrorAuthority)
	var peers []*config.Authority
	var order []*internalErrorAuthority
	for i := 0; i < 3; i++ {
		peer, _, idPub, linkPriv, err := generatePeer(42300 + i)
		require.NoError(t, err)
		peers = append(peers, peer)
		u, err := url.Parse(peer.Addresses[0])
		require.NoError(t, err)
		a := &internalErrorAuthority{linkKey: linkPriv, idKey: idPub}
		auths[u.Host] = a
		order = append(order, a)
	}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		cc, sc := net.Pipe()
		go auths[address].serve(sc, g)
		return cc, nil
	}
	_, linkKey, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)
	cfg := &Config{
		KEMScheme:           testingScheme,
		LogBackend:          logBackend,
		LinkKey:             linkKey,
		Authorities:         peers,
		DialContextFn:       dial,
		Geo:                 g,
		DialTimeoutSec:      30,
		HandshakeTimeoutSec: 30,
		ResponseTimeoutSec:  30,
	}
	require.NoError(t, cfg.validate())
	c, err := New(cfg)
	require.NoError(t, err)

	idPub, idPriv, err := testSignatureScheme.GenerateKey()
	require.NoError(t, err)
	epoch, _, _ := epochtime.Now()
	desc := generateReplicaDescriptorForPostReplicaTest(t, epoch, idPub)

	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	defer cancel()
	err = c.PostReplica(ctx, epoch, idPriv, idPub, desc)
	require.Error(t, err)
	require.NotErrorIs(t, err, pki.ErrInvalidPostEpoch)
	for _, a := range order {
		require.Greater(t, a.posts.Load(), int32(1))
	}
	b, err := os.ReadFile(logPath)
	require.NoError(t, err)
	require.Contains(t, string(b), "WARN")
	require.Contains(t, string(b), peers[0].Identifier+" reported an internal error")
}
