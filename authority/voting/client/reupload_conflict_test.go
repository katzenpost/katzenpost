// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"net"
	"net/url"
	"sync"
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

type oldAuthority struct {
	linkKey  kem.PrivateKey
	idKey    sign.PublicKey
	lagFirst bool

	mu       sync.Mutex
	stored   bool
	attempts int
}

func (a *oldAuthority) IsPeerValid(*wire.PeerCredentials) bool {
	return true
}

func (a *oldAuthority) answer() uint8 {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.attempts++
	switch {
	case a.stored:
		return commands.DescriptorConflict
	case a.lagFirst && a.attempts == 1:
		return commands.DescriptorInvalid
	}
	a.stored = true
	return commands.DescriptorOk
}

func (a *oldAuthority) serve(c net.Conn, g *geo.Geometry) {
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
	s.SendCommand(context.Background(), &commands.PostReplicaDescriptorStatus{ErrorCode: a.answer()})
}

func oldAuthorityClient(t *testing.T, lagFirst []bool, base int) *Client {
	logBackend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	g := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5)

	auths := make(map[string]*oldAuthority)
	var peers []*config.Authority
	for i, lag := range lagFirst {
		peer, _, idPub, linkPriv, err := generatePeer(base + i)
		require.NoError(t, err)
		peers = append(peers, peer)
		u, err := url.Parse(peer.Addresses[0])
		require.NoError(t, err)
		auths[u.Host] = &oldAuthority{linkKey: linkPriv, idKey: idPub, lagFirst: lag}
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
	return c.(*Client)
}

type reuploadPoster func(t *testing.T, c *Client, epoch uint64, same bool) error

func reuploadPosters(t *testing.T) map[string]reuploadPoster {
	return map[string]reuploadPoster{
		"mix": func() reuploadPoster {
			var desc *pki.MixDescriptor
			var idPriv sign.PrivateKey
			var idPub sign.PublicKey
			return func(t *testing.T, c *Client, epoch uint64, same bool) error {
				if desc == nil || !same {
					desc, idPriv, idPub = generateMixDescriptorForPostTest(t, epoch, 43000)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
				defer cancel()
				return c.Post(ctx, epoch, idPriv, idPub, desc, nil)
			}
		}(),
		"replica": func() reuploadPoster {
			idPub, idPriv, err := testSignatureScheme.GenerateKey()
			require.NoError(t, err)
			var desc *pki.ReplicaDescriptor
			return func(t *testing.T, c *Client, epoch uint64, same bool) error {
				if desc == nil || !same {
					desc = generateReplicaDescriptorForPostReplicaTest(t, epoch, idPub)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
				defer cancel()
				return c.PostReplica(ctx, epoch, idPriv, idPub, desc)
			}
		}(),
	}
}

func TestRepostCountsAConflictFromAnEarlierAccepterAsAccepted(t *testing.T) {
	base := 43100
	for name, post := range reuploadPosters(t) {
		base += 10
		t.Run(name, func(t *testing.T) {
			c := oldAuthorityClient(t, []bool{false, false, true, true}, base)
			epoch, _, _ := epochtime.Now()
			err := post(t, c, epoch+1, true)
			require.Error(t, err)
			require.NotErrorIs(t, err, pki.ErrInvalidPostEpoch)
			require.NoError(t, post(t, c, epoch+1, true))
		})
	}
}

func TestRepostOfADifferentDescriptorInheritsNoAcceptance(t *testing.T) {
	base := 43200
	for name, post := range reuploadPosters(t) {
		base += 10
		t.Run(name, func(t *testing.T) {
			c := oldAuthorityClient(t, []bool{false, false, true, true}, base)
			epoch, _, _ := epochtime.Now()
			require.Error(t, post(t, c, epoch+1, true))
			err := post(t, c, epoch+1, false)
			require.Error(t, err)
			require.NotErrorIs(t, err, pki.ErrInvalidPostEpoch)
		})
	}
}
