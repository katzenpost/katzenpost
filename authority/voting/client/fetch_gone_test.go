// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"errors"
	"net"
	"net/url"
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

const unreachable = -1

type codeAuthority struct {
	code    int
	linkKey kem.PrivateKey
	idKey   sign.PublicKey
}

func (a *codeAuthority) IsPeerValid(*wire.PeerCredentials) bool {
	return true
}

func (a *codeAuthority) serve(c net.Conn, g *geo.Geometry) {
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
	s.SendCommand(context.Background(), &commands.Consensus{ErrorCode: uint8(a.code)})
}

func fetchWithCodes(t *testing.T, codes []int, base int) error {
	logBackend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	g := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5)

	auths := make(map[string]*codeAuthority)
	var peers []*config.Authority
	for i, code := range codes {
		peer, _, idPub, linkPriv, err := generatePeer(base + i)
		require.NoError(t, err)
		peers = append(peers, peer)
		u, err := url.Parse(peer.Addresses[0])
		require.NoError(t, err)
		auths[u.Host] = &codeAuthority{code: code, linkKey: linkPriv, idKey: idPub}
	}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		a := auths[address]
		if a.code == unreachable {
			return nil, errors.New("connection refused")
		}
		cc, sc := net.Pipe()
		go a.serve(sc, g)
		return cc, nil
	}

	cfg := &Config{
		KEMScheme:           testingScheme,
		LogBackend:          logBackend,
		Authorities:         peers,
		DialContextFn:       dial,
		Geo:                 g,
		DialTimeoutSec:      5,
		HandshakeTimeoutSec: 5,
		ResponseTimeoutSec:  5,
		RetryMaxAttempts:    1,
	}
	require.NoError(t, cfg.validate())
	c, err := New(cfg)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	epoch, _, _ := epochtime.Now()
	_, _, err = c.GetPKIDocumentForEpoch(ctx, epoch)
	return err
}

func TestGetPKIDocumentGoneOnlyWhenAuthoritiesSaySo(t *testing.T) {
	t.Parallel()
	gone, notFound := commands.ConsensusGone, commands.ConsensusNotFound
	cases := []struct {
		name  string
		codes []int
		want  error
	}{
		{"all unreachable", []int{unreachable, unreachable, unreachable}, pki.ErrNoDocument},
		{"unreachable and not found", []int{unreachable, notFound, unreachable}, pki.ErrNoDocument},
		{"one gone, rest unreachable", []int{gone, unreachable, unreachable}, pki.ErrNoDocument},
		{"too few gone to rule out a consensus", []int{gone, gone, unreachable, unreachable, notFound}, pki.ErrNoDocument},
		{"all gone", []int{gone, gone, gone}, pki.ErrDocumentGone},
		{"enough gone to rule out a consensus", []int{gone, gone, unreachable}, pki.ErrDocumentGone},
		{"enough gone among five", []int{gone, gone, gone, unreachable, notFound}, pki.ErrDocumentGone},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, fetchWithCodes(t, tc.codes, 41000+i*10))
		})
	}
}
