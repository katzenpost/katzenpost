// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func postLogWithCodes(t *testing.T, codes []uint8, base int) string {
	logFile := filepath.Join(t.TempDir(), "post.log")
	logBackend, err := log.New(logFile, "WARNING", false)
	require.NoError(t, err)
	g := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5)

	auths := make(map[string]*postStatusAuthority)
	var peers []*config.Authority
	for i, code := range codes {
		peer, _, idPub, linkPriv, err := generatePeer(base + i)
		require.NoError(t, err)
		peers = append(peers, peer)
		u, err := url.Parse(peer.Addresses[0])
		require.NoError(t, err)
		auths[u.Host] = &postStatusAuthority{code: code, linkKey: linkPriv, idKey: idPub}
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
	require.Error(t, c.PostReplica(ctx, epoch, idPriv, idPub, desc))
	b, err := os.ReadFile(logFile)
	require.NoError(t, err)
	return string(b)
}

func TestPostRejectionLogNamesTheStatus(t *testing.T) {
	t.Parallel()
	for i, tc := range []struct {
		code uint8
		text string
	}{
		{commands.DescriptorInvalid, "rejected (Invalid)"},
		{commands.DescriptorForbidden, "rejected (Forbidden)"},
	} {
		t.Run(tc.text, func(t *testing.T) {
			t.Parallel()
			out := postLogWithCodes(t, []uint8{tc.code, tc.code, tc.code}, 42200+i*10)
			require.Contains(t, out, tc.text)
			require.NotContains(t, strings.ToLower(out), "conflict")
		})
	}
}
