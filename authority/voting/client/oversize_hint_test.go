// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func oversizedFetchLog(t *testing.T, base int, tune func(*Config)) string {
	p := filepath.Join(t.TempDir(), "client.log")
	logBackend, err := log.New(p, "WARNING", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logBackend.Close() })
	g := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5)

	peer, _, idPub, linkPriv, err := generatePeer(base)
	require.NoError(t, err)
	u, err := url.Parse(peer.Addresses[0])
	require.NoError(t, err)
	serve := func(c net.Conn) {
		defer c.Close()
		id := hash.Sum256From(idPub)
		s, err := wire.NewPKISession(&wire.SessionConfig{
			KEMScheme:         testingScheme,
			Geometry:          g,
			Authenticator:     &codeAuthority{},
			AdditionalData:    id[:],
			AuthenticationKey: linkPriv,
			RandomReader:      rand.Reader,
			MaxMessageSize:    1 << 20,
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
		s.SendCommand(context.Background(), &commands.Consensus{ErrorCode: commands.ConsensusOk, Payload: make([]byte, 256*1024)})
	}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		require.Equal(t, u.Host, address)
		cc, sc := net.Pipe()
		go serve(sc)
		return cc, nil
	}
	cfg := &Config{
		KEMScheme:           testingScheme,
		LogBackend:          logBackend,
		Authorities:         []*config.Authority{peer},
		DialContextFn:       dial,
		Geo:                 g,
		DialTimeoutSec:      5,
		HandshakeTimeoutSec: 5,
		ResponseTimeoutSec:  5,
		RetryMaxAttempts:    1,
		MaxConsensusSize:    64 * 1024,
	}
	tune(cfg)
	require.NoError(t, cfg.validate())
	c, err := New(cfg)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	epoch, _, _ := epochtime.Now()
	_, _, err = c.GetPKIDocumentForEpoch(ctx, epoch)
	require.Error(t, err)
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	return string(b)
}

func TestOversizedReplyWarningNamesNoAbsentSetting(t *testing.T) {
	out := oversizedFetchLog(t, 41500, func(*Config) {})
	require.Contains(t, out, "reply exceeded")
	require.NotContains(t, out, "set MaxConsensusSize explicitly")
}

func TestOversizedReplyWarningNamesConfiguredSetting(t *testing.T) {
	out := oversizedFetchLog(t, 41510, func(cfg *Config) {
		cfg.MaxConsensusSizeSetting = "PKI.Voting.MaxConsensusSize"
	})
	require.Contains(t, out, "reply exceeded our consensus size ceiling (65536 bytes); if the network has grown, raise PKI.Voting.MaxConsensusSize")
}
