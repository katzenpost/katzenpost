// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/quic/common"
)

func countLogged(t *testing.T, logFile, needle string) int {
	t.Helper()
	logged, err := os.ReadFile(logFile)
	require.NoError(t, err)
	return strings.Count(string(logged), needle)
}

func TestPinMismatchFallsBackToTCPWithinTheDial(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	a := newQUICAuthorityKeys(t)
	impostorKeys, _ := fixedEpochKeys(t, epoch)
	impostor := a.servePosts(t, impostorKeys)
	var tcpDials atomic.Int32
	tcp := a.serveTCPPosts(t, &tcpDials)
	_, linkKey, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)

	sawPinnedDial := false
	for range 16 {
		logFile := filepath.Join(t.TempDir(), "client.log")
		c, peer := a.postingClient(t, logFile)
		peer.QUICKeyHash = bytes.Repeat([]byte{2}, pki.QUICKeyHashSize)
		peer.Addresses = []string{impostor, tcp}
		conn, err := c.pool.initSession(context.Background(), linkKey, nil, peer)
		if conn != nil {
			conn.Close()
		}
		if countLogged(t, logFile, "quic dial pinned to its configured QUIC key hash") == 0 {
			continue
		}
		sawPinnedDial = true
		require.NoError(t, err, "a pin mismatch on quic did not fall back to the authority's tcp address")
	}
	require.True(t, sawPinnedDial)
}

func TestPinMismatchKeepsThePeerOffQUICForTheEpoch(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	a := newQUICAuthorityKeys(t)
	impostorKeys, _ := fixedEpochKeys(t, epoch)
	impostor := a.servePosts(t, impostorKeys)
	var tcpDials atomic.Int32
	tcp := a.serveTCPPosts(t, &tcpDials)
	logFile := filepath.Join(t.TempDir(), "client.log")
	c, peer := a.postingClient(t, logFile)
	peer.QUICKeyHash = bytes.Repeat([]byte{2}, pki.QUICKeyHashSize)
	_, linkKey, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)

	peer.Addresses = []string{impostor}
	_, err = c.pool.initSession(context.Background(), linkKey, nil, peer)
	require.ErrorIs(t, err, common.ErrQUICKeyMismatch)
	pinned := countLogged(t, logFile, "quic dial pinned to its configured QUIC key hash")

	peer.Addresses = []string{impostor, tcp}
	for range 4 {
		conn, err := c.pool.initSession(context.Background(), linkKey, nil, peer)
		require.NoError(t, err, "a peer that failed its pin this epoch was not dialed over tcp")
		conn.Close()
	}
	require.Equal(t, pinned, countLogged(t, logFile, "quic dial pinned to its configured QUIC key hash"), "a peer that failed its pin this epoch was dialed over quic again")
}

func TestPostPinMismatchFallsBackToTCP(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	a := newQUICAuthorityKeys(t)
	impostorKeys, _ := fixedEpochKeys(t, epoch)
	impostor := a.servePosts(t, impostorKeys)
	var tcpPosts atomic.Int32
	tcp := a.serveTCPPosts(t, &tcpPosts)
	c, peer := a.postingClient(t, filepath.Join(t.TempDir(), "client.log"))
	peer.QUICKeyHash = bytes.Repeat([]byte{2}, pki.QUICKeyHashSize)
	_, linkKey, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)
	peer.Addresses = []string{impostor}
	_, err = c.pool.initSession(context.Background(), linkKey, nil, peer)
	require.ErrorIs(t, err, common.ErrQUICKeyMismatch)

	idPub, idPriv, err := signSchemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	peer.Addresses = []string{impostor, tcp}
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	defer cancel()
	require.NoError(t, c.PostReplica(ctx, epoch, idPriv, idPub, generateReplicaDescriptorForPostReplicaTest(t, epoch, idPub)), "a post after a pin mismatch did not fall back to tcp")
	require.NotZero(t, tcpPosts.Load())
}

func TestPostPinMismatchStaysPendingUnderFallback(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	a := newQUICAuthorityKeys(t)
	impostorKeys, _ := fixedEpochKeys(t, epoch)
	impostor := a.servePosts(t, impostorKeys)
	logFile := filepath.Join(t.TempDir(), "client.log")
	c, peer := a.postingClient(t, logFile)
	peer.QUICKeyHash = bytes.Repeat([]byte{2}, pki.QUICKeyHashSize)
	peer.Addresses = []string{impostor}

	idPub, idPriv, err := signSchemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	require.Error(t, c.PostReplica(ctx, epoch, idPriv, idPub, generateReplicaDescriptorForPostReplicaTest(t, epoch, idPub)))
	require.GreaterOrEqual(t, countLogged(t, logFile, "post authority auth1: attempt failed"), 2, "a pin mismatch settled the post to this authority for the epoch")
}
