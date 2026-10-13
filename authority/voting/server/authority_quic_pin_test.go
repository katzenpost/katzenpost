// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/quic/common"
)

func listenQUICAuthority(t *testing.T, s *state, keys *common.EpochKeys) string {
	t.Helper()
	l, err := common.ListenWithEpochKeys("127.0.0.1:0", s.s.identityPrivateKey, keys)
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

func TestPeerDialIsPinnedOnceAConsensusNamesItsKeys(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	epoch += 1
	var states []*state
	runVoteScenarioWith(t, 3, epoch, nil, func(s []*state) {
		states = s
		for _, st := range s {
			optInQUICKeyHashes(t, st, epoch)
		}
	})
	dialer, target := states[0], states[1]
	impostorKeys, err := common.NewEpochKeys(t.TempDir(), common.CurrentEpoch)
	require.NoError(t, err)
	_, err = impostorKeys.Hashes(epoch - 1)
	require.NoError(t, err)
	genuine := listenQUICAuthority(t, target, target.s.quicKeys)
	impostor := listenQUICAuthority(t, target, impostorKeys)
	out := fileLogged(t, dialer)
	peer := &config.Authority{Identifier: "auth1", IdentityPublicKey: target.s.identityPublicKey}

	conn, err := dialer.dialPeerAddrs(peer, []string{genuine}, 5*time.Second)
	require.NoError(t, err, "a dial to the key the consensus names must succeed")
	conn.Close()

	_, err = dialer.dialPeerAddrs(peer, []string{impostor}, 5*time.Second)
	require.Error(t, err, "a peer dial accepted a key the consensus does not name")
	require.ErrorContains(t, err, "QUIC key does not match")
	require.Contains(t, out(), "peer auth1: quic dial pinned to 3 consensus QUIC key hashes")
}

func TestPeerDialWithoutAConsensusIsUnpinned(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	states, _ := buildScenarioStates(t, 3, epoch+1, nil)
	t.Cleanup(func() {
		for _, s := range states {
			close(s.s.haltedCh)
			s.db.Close()
		}
	})
	dialer, target := states[0], states[1]
	keys, err := common.NewEpochKeys(t.TempDir(), common.CurrentEpoch)
	require.NoError(t, err)
	_, err = keys.Hashes(epoch)
	require.NoError(t, err)
	addr := listenQUICAuthority(t, target, keys)
	out := fileLogged(t, dialer)
	peer := &config.Authority{Identifier: "auth1", IdentityPublicKey: target.s.identityPublicKey}
	conn, err := dialer.dialPeerAddrs(peer, []string{addr}, 5*time.Second)
	require.NoError(t, err, "a bootstrap dial with no consensus must succeed unpinned")
	conn.Close()
	require.Contains(t, out(), "peer auth1: quic dial unpinned, no QUIC key hashes known")
}
