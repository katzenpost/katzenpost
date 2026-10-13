// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/quic/common"
)

var (
	unpinnedPeerDialWarning = regexp.MustCompile(`WARN [^\n]*peer auth1: quic dial unpinned, no QUIC key hashes known`)
	unpinnedPeerDialDebug   = regexp.MustCompile(`DEBU [^\n]*peer auth1: quic dial unpinned, no QUIC key hashes known`)
)

func TestUnpinnedPeerDialWarnsOnlyWhenTheConsensusWithholdsHashes(t *testing.T) {
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
	addr := listenQUICAuthority(t, target, keys)
	out := fileLogged(t, dialer)
	peer := &config.Authority{Identifier: "auth1", IdentityPublicKey: target.s.identityPublicKey}
	dial := func() {
		conn, err := dialer.dialPeerAddrs(peer, []string{addr}, 5*time.Second)
		require.NoError(t, err)
		conn.Close()
	}

	dial()
	require.Regexp(t, unpinnedPeerDialDebug, out(), "a bootstrap dial with no consensus yet must log at debug")
	require.NotRegexp(t, unpinnedPeerDialWarning, out(), "a bootstrap dial with no consensus yet must not warn")

	dialer.quicPins.Learn(&pki.Document{Epoch: epoch})
	dial()
	dial()
	require.Len(t, unpinnedPeerDialWarning.FindAllString(out(), -1), 1, "a consensus without AuthorityQUICKeyHashes must warn once per epoch")
}
