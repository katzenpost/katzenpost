// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"bytes"
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/quic/common"
)

func TestPinMismatchKeepsThePeerOffUnpinnedAddressesForTheEpoch(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	a := newQUICAuthorityKeys(t)
	impostorKeys, _ := fixedEpochKeys(t, epoch)
	impostor := a.servePosts(t, impostorKeys)
	var tcpDials atomic.Int32
	tcp := a.serveTCPPosts(t, &tcpDials)
	c, peer := a.postingClient(t, filepath.Join(t.TempDir(), "client.log"))
	peer.QUICKeyHash = bytes.Repeat([]byte{2}, pki.QUICKeyHashSize)
	_, linkKey, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)

	peer.Addresses = []string{impostor}
	_, err = c.pool.initSession(context.Background(), linkKey, nil, peer)
	require.ErrorIs(t, err, common.ErrQUICKeyMismatch)

	peer.Addresses = []string{tcp}
	conn, err := c.pool.initSession(context.Background(), linkKey, nil, peer)
	if conn != nil {
		conn.Close()
	}
	require.Zero(t, tcpDials.Load(), "a peer that failed its pin this epoch was dialed over unpinned tcp")
	require.Error(t, err)
}
