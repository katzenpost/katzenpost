// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/quic/common"
)

func TestPeerPinMismatchDoesNotFallBackToTCP(t *testing.T) {
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
	impostor := listenQUICAuthority(t, target, impostorKeys)
	var dialed atomic.Int32
	dialer.dialContextFn = func(context.Context, string, string) (net.Conn, error) {
		dialed.Add(1)
		return nil, errors.New("unpinned dial")
	}
	peer := &config.Authority{Identifier: "auth1", IdentityPublicKey: target.s.identityPublicKey}

	_, err = dialer.dialPeerAddrs(peer, []string{impostor, "tcp://127.0.0.1:9"}, 5*time.Second)
	require.ErrorContains(t, err, "QUIC key does not match")
	require.Zero(t, dialed.Load(), "a pin mismatch on quic fell back to an unpinned tcp dial of the same authority")
}
