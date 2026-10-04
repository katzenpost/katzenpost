// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"net"
	"net/url"
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

type postStatusAuthority struct {
	code    uint8
	linkKey kem.PrivateKey
	idKey   sign.PublicKey
	posts   atomic.Int32
}

func (a *postStatusAuthority) IsPeerValid(*wire.PeerCredentials) bool {
	return true
}

func (a *postStatusAuthority) serve(c net.Conn, g *geo.Geometry) {
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
	s.SendCommand(context.Background(), &commands.PostReplicaDescriptorStatus{ErrorCode: a.code})
}

func postWithCodes(t *testing.T, codes []uint8, base int) (error, []int32) {
	logBackend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	g := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5)

	auths := make(map[string]*postStatusAuthority)
	var peers []*config.Authority
	var order []*postStatusAuthority
	for i, code := range codes {
		peer, _, idPub, linkPriv, err := generatePeer(base + i)
		require.NoError(t, err)
		peers = append(peers, peer)
		u, err := url.Parse(peer.Addresses[0])
		require.NoError(t, err)
		a := &postStatusAuthority{code: code, linkKey: linkPriv, idKey: idPub}
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
	posts := make([]int32, len(order))
	for i, a := range order {
		posts[i] = a.posts.Load()
	}
	return err, posts
}

func TestPostRejectionQuorumIsPermanent(t *testing.T) {
	t.Parallel()
	inv, conf, forb := uint8(commands.DescriptorInvalid), uint8(commands.DescriptorConflict), uint8(commands.DescriptorForbidden)
	cases := []struct {
		name      string
		codes     []uint8
		permanent bool
	}{
		{"all forbidden", []uint8{forb, forb, forb}, true},
		{"all invalid", []uint8{inv, inv, inv}, true},
		{"mixed rejections", []uint8{conf, inv, 0xfe}, true},
		{"unknown code", []uint8{0xfe, 0xfe, 0xfe}, false},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			err, posts := postWithCodes(t, tc.codes, 42000+i*10)
			if tc.permanent {
				require.ErrorIs(t, err, pki.ErrInvalidPostEpoch)
				require.Less(t, time.Since(start), 5*time.Second)
				return
			}
			require.Error(t, err)
			require.NotErrorIs(t, err, pki.ErrInvalidPostEpoch)
			for _, n := range posts {
				require.Greater(t, n, int32(1))
			}
		})
	}
}

func TestPostDoesNotRetryARejectingAuthority(t *testing.T) {
	t.Parallel()
	ok, forb := uint8(commands.DescriptorOk), uint8(commands.DescriptorForbidden)
	err, posts := postWithCodes(t, []uint8{ok, ok, forb}, 42100)
	require.NoError(t, err)
	require.Equal(t, int32(1), posts[2])
}
