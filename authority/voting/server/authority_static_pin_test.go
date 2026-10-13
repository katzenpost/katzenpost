// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
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

func listenQUICAuthority(t *testing.T, s *state, keys *common.EpochKeys) string {
	t.Helper()
	l, err := common.ListenWithEpochKeys("127.0.0.1:0", s.s.identityPrivateKey, keys, nil)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	return "quic://" + l.Addr().String()
}

func TestPeerDialIsPinnedToItsConfiguredKeyFromTheFirstDial(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	states, _ := buildScenarioStates(t, 3, epoch+1, nil)
	t.Cleanup(func() {
		for _, s := range states {
			close(s.s.haltedCh)
			s.db.Close()
		}
	})
	dialer, target := states[0], states[1]
	genuineKeys, genuineHash := fixedEpochKeys(t, epoch)
	impostorKeys, _ := fixedEpochKeys(t, epoch)
	genuine := listenQUICAuthority(t, target, genuineKeys)
	impostor := listenQUICAuthority(t, target, impostorKeys)
	out := fileLogged(t, dialer)
	peer := &config.Authority{Identifier: "auth1", IdentityPublicKey: target.s.identityPublicKey, QUICKeyHash: genuineHash}

	_, err := dialer.dialPeerAddrs(peer, []string{impostor}, 5*time.Second)
	require.ErrorIs(t, err, common.ErrQUICKeyMismatch, "the first quic dial to a peer accepted a key other than its QUICKeyHash")

	conn, err := dialer.dialPeerAddrs(peer, []string{genuine}, 5*time.Second)
	require.NoError(t, err, "a dial to the configured key must succeed")
	conn.Close()
	require.Contains(t, out(), "peer auth1: quic dial pinned to its configured QUIC key hash")

	peer.QUICKeyHash = nil
	_, err = dialer.dialPeerAddrs(peer, []string{genuine}, 5*time.Second)
	require.Error(t, err, "a peer without a QUICKeyHash was dialed over quic")
	require.Contains(t, out(), "peer auth1: no QUIC key hash configured, not dialing "+genuine)
}
