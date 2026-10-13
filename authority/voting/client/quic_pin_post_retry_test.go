// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"bytes"
	"context"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/retry"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/quic/common"
)

func (a *quicAuthorityKeys) answerPost(conn net.Conn) {
	defer conn.Close()
	identityHash := hash.Sum256From(a.identityPublicKey)
	session, err := wire.NewPKISession(&wire.SessionConfig{
		KEMScheme:         testingScheme,
		Geometry:          a.geo,
		Authenticator:     acceptAnyPeer{},
		AdditionalData:    identityHash[:],
		AuthenticationKey: a.linkPrivateKey,
		RandomReader:      rand.Reader,
	}, false)
	if err != nil {
		return
	}
	defer session.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := session.Initialize(ctx, conn); err != nil {
		return
	}
	if _, err := session.RecvCommand(ctx); err != nil {
		return
	}
	_ = session.SendCommand(ctx, &commands.PostReplicaDescriptorStatus{ErrorCode: commands.DescriptorOk})
}

func (a *quicAuthorityKeys) servePosts(t *testing.T, keys *common.EpochKeys) string {
	t.Helper()
	l, err := common.ListenWithEpochKeys("127.0.0.1:0", a.identityPrivateKey, keys, nil)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go a.answerPost(conn)
		}
	}()
	return "quic://" + l.Addr().String()
}

func (a *quicAuthorityKeys) serveTCPPosts(t *testing.T, posts *atomic.Int32) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			posts.Add(1)
			go a.answerPost(conn)
		}
	}()
	return "tcp://" + l.Addr().String()
}

func (a *quicAuthorityKeys) postingClient(t *testing.T, logFile string) (*Client, *config.Authority) {
	t.Helper()
	backend, err := log.New(logFile, "DEBUG", false)
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })
	_, linkKey, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)
	peer := &config.Authority{
		Identifier:        "auth1",
		WireKEMScheme:     testingSchemeName,
		IdentityPublicKey: a.identityPublicKey,
		LinkPublicKey:     config.LinkPublicKey{PublicKey: a.linkPrivateKey.Public()},
	}
	c, err := New(&Config{
		KEMScheme:          testingScheme,
		PKISignatureScheme: signSchemes.ByName(testSchemeName),
		LogBackend:         backend,
		LinkKey:            linkKey,
		Authorities:        []*config.Authority{peer},
		Geo:                a.geo,
		DialTimeoutSec:     5,
		RetryMaxAttempts:   1,
		RetryBaseDelay:     time.Millisecond,
		RetryMaxDelay:      time.Millisecond,
	})
	require.NoError(t, err)
	return c.(*Client), peer
}

func TestPostPinMismatchDoesNotRetryOverUnpinnedTCP(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	a := newQUICAuthorityKeys(t)
	genuineKeys, genuineHash := fixedEpochKeys(t, epoch)
	impostorKeys, _ := fixedEpochKeys(t, epoch)
	genuine := a.serve(t, genuineKeys, a.consensus(t, epoch))
	impostor := a.servePosts(t, impostorKeys)
	var tcpPosts atomic.Int32
	tcp := a.serveTCPPosts(t, &tcpPosts)

	logFile := filepath.Join(t.TempDir(), "client.log")
	c, peer := a.postingClient(t, logFile)
	peer.QUICKeyHash = genuineHash
	peer.Addresses = []string{genuine}
	require.NoError(t, fetch(t, c, epoch), "bootstrap")

	idPub, idPriv, err := signSchemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	desc := generateReplicaDescriptorForPostReplicaTest(t, epoch, idPub)

	pinnedDials := func() int {
		logged, err := os.ReadFile(logFile)
		require.NoError(t, err)
		return strings.Count(string(logged), "quic dial pinned to its configured QUIC key hash")
	}
	peer.Addresses = []string{impostor, tcp}
	sawPinnedDial := false
	for range 12 {
		before, postsBefore := pinnedDials(), tcpPosts.Load()
		ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
		err := c.PostReplica(ctx, epoch, idPriv, idPub, desc)
		cancel()
		t.Logf("PostReplica: err=%v pinned dials %d->%d tcp posts %d->%d", err, before, pinnedDials(), postsBefore, tcpPosts.Load())
		if pinnedDials() == before {
			continue
		}
		sawPinnedDial = true
		require.Equal(t, postsBefore, tcpPosts.Load(), "after a pin mismatch on quic the completion rounds re-dialed the same authority over unpinned tcp")
	}
	require.True(t, sawPinnedDial)
}

func TestPinMismatchIsNotATransientDialError(t *testing.T) {
	impostor, err := quic.ListenAddr("127.0.0.1:0", common.GenerateTLSConfig(), common.Config())
	require.NoError(t, err)
	t.Cleanup(func() { impostor.Close() })
	u, err := url.Parse("quic://" + impostor.Addr().String())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = common.DialURL(u, ctx, nil, bytes.Repeat([]byte{2}, 3*pki.QUICKeyHashSize), nil)
	require.ErrorIs(t, err, common.ErrQUICKeyMismatch)
	require.False(t, retry.IsTransientError(err), "%v", err)
}

func TestPinMismatchFromInitSessionIsNotTransient(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	a := newQUICAuthorityKeys(t)
	impostorKeys, _ := fixedEpochKeys(t, epoch)
	impostor := a.servePosts(t, impostorKeys)
	c, peer := a.postingClient(t, filepath.Join(t.TempDir(), "client.log"))
	peer.Addresses = []string{impostor}
	peer.QUICKeyHash = bytes.Repeat([]byte{2}, pki.QUICKeyHashSize)
	_, linkKey, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)
	_, err = c.pool.initSession(context.Background(), linkKey, nil, peer)
	require.ErrorIs(t, err, common.ErrQUICKeyMismatch)
	require.False(t, retry.IsTransientError(err), "%v", err)
}
