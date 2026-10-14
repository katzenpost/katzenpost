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
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/quic/common"
)

func TestPeerPinMismatchDoesNotFallBackToTCP(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	states, _ := buildScenarioStates(t, 3, epoch+1, nil)
	t.Cleanup(func() {
		for _, s := range states {
			close(s.s.haltedCh)
			s.db.Close()
		}
	})
	dialer, target := states[0], states[1]
	dialer.s.cfg.QUIC = &common.Options{PinMismatch: common.PinMismatchStrict}
	impostorKeys, _ := fixedEpochKeys(t, epoch)
	impostor := listenQUICAuthority(t, target, impostorKeys)
	var dialed atomic.Int32
	dialer.dialContextFn = func(context.Context, string, string) (net.Conn, error) {
		dialed.Add(1)
		return nil, errors.New("unpinned dial")
	}
	peer := &config.Authority{Identifier: "auth1", IdentityPublicKey: target.s.identityPublicKey, QUICKeyHash: make([]byte, pki.QUICKeyHashSize)}

	_, err := dialer.dialPeerAddrs(peer, []string{impostor, "tcp://127.0.0.1:9"}, 5*time.Second)
	require.ErrorContains(t, err, "QUIC key does not match")
	require.Zero(t, dialed.Load(), "a pin mismatch on quic fell back to an unpinned tcp dial of the same authority")
}
