// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
)

func TestPeerPinMismatchFallsBackToTCPForTheEpoch(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	states, _ := buildScenarioStates(t, 3, epoch+1, nil)
	t.Cleanup(func() {
		for _, s := range states {
			close(s.s.haltedCh)
			s.db.Close()
		}
	})
	dialer, target := states[0], states[1]
	impostorKeys, _ := fixedEpochKeys(t, epoch)
	impostor := listenQUICAuthority(t, target, impostorKeys)
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { tcp.Close() })
	out := fileLogged(t, dialer)
	peer := &config.Authority{Identifier: "auth1", IdentityPublicKey: target.s.identityPublicKey, QUICKeyHash: make([]byte, pki.QUICKeyHashSize)}
	addrs := []string{impostor, "tcp://" + tcp.Addr().String()}

	conn, err := dialer.dialPeerAddrs(peer, addrs, 5*time.Second)
	require.NoError(t, err, "a pin mismatch on quic did not fall back to the authority's tcp address")
	conn.Close()
	pinned := strings.Count(out(), "quic dial pinned to its configured QUIC key hash")

	conn, err = dialer.dialPeerAddrs(peer, addrs, 5*time.Second)
	require.NoError(t, err)
	conn.Close()
	require.Equal(t, pinned, strings.Count(out(), "quic dial pinned to its configured QUIC key hash"), "a peer that failed its pin this epoch was dialed over quic again")
}
