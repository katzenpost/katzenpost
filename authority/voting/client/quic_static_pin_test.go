// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/quic/common"
)

func fixedEpochKeys(t *testing.T, epoch uint64) (*common.EpochKeys, []byte) {
	t.Helper()
	keys, err := common.NewEpochKeys(t.TempDir(), func() uint64 { return epoch })
	require.NoError(t, err)
	hashes, err := keys.Hashes(epoch)
	require.NoError(t, err)
	return keys, hashes[pki.QUICKeyHashSize : 2*pki.QUICKeyHashSize]
}

func TestAuthorityDialIsPinnedToItsConfiguredKeyFromTheFirstDial(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	a := newQUICAuthorityKeys(t)
	genuineKeys, genuineHash := fixedEpochKeys(t, epoch)
	impostorKeys, _ := fixedEpochKeys(t, epoch)
	consensus := a.consensus(t, epoch)
	genuine := a.serve(t, genuineKeys, consensus)
	impostor := a.serve(t, impostorKeys, consensus)

	logFile := filepath.Join(t.TempDir(), "client.log")
	c, peer := a.client(t, logFile)
	peer.QUICKeyHash = genuineHash
	peer.Addresses = []string{impostor}
	require.Error(t, fetch(t, c, epoch), "the first quic dial to an authority accepted a key other than its QUICKeyHash")

	peer.Addresses = []string{genuine}
	require.NoError(t, fetch(t, c, epoch), "a dial to the configured key must succeed")
	logged, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.Contains(t, string(logged), "peer auth1: quic dial pinned to its configured QUIC key hash")
}

func TestAuthorityWithoutAQUICKeyHashIsNotDialedOverQUIC(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	a := newQUICAuthorityKeys(t)
	keys, _ := fixedEpochKeys(t, epoch)
	consensus := a.consensus(t, epoch)
	quic := a.serve(t, keys, consensus)
	var tcpDials atomic.Int32
	tcp := a.serveTCP(t, consensus, &tcpDials)

	logFile := filepath.Join(t.TempDir(), "client.log")
	c, peer := a.client(t, logFile)
	peer.Addresses = []string{quic}
	require.Error(t, fetch(t, c, epoch), "an authority without a QUICKeyHash was dialed over quic")

	peer.Addresses = []string{quic, tcp}
	require.NoError(t, fetch(t, c, epoch), "an authority without a QUICKeyHash must still be dialed over tcp")
	require.Equal(t, int32(1), tcpDials.Load())
	logged, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.Contains(t, string(logged), "peer auth1: no QUIC key hash configured, not dialing "+quic)
}
