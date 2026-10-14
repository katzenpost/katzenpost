// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/quic/common"
)

func (a *quicAuthorityKeys) serveTCP(t *testing.T, consensus []byte, dialed *atomic.Int32) string {
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
			dialed.Add(1)
			go a.answer(conn, consensus)
		}
	}()
	return "tcp://" + l.Addr().String()
}

func TestPinMismatchDoesNotFallBackToTCP(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	a := newQUICAuthorityKeys(t)
	genuineKeys, genuineHash := fixedEpochKeys(t, epoch)
	impostorKeys, _ := fixedEpochKeys(t, epoch)
	consensus := a.consensus(t, epoch)
	genuine := a.serve(t, genuineKeys, consensus)
	impostor := a.serve(t, impostorKeys, consensus)
	var dialed atomic.Int32
	tcp := a.serveTCP(t, consensus, &dialed)

	logFile := filepath.Join(t.TempDir(), "client.log")
	c, peer := a.client(t, logFile)
	c.cfg.QUIC = &common.Options{PinMismatch: common.PinMismatchStrict}
	peer.QUICKeyHash = genuineHash
	peer.Addresses = []string{genuine}
	require.NoError(t, fetch(t, c, epoch), "bootstrap")

	pinnedDials := func() int {
		logged, err := os.ReadFile(logFile)
		require.NoError(t, err)
		return strings.Count(string(logged), "quic dial pinned to its configured QUIC key hash")
	}
	peer.Addresses = []string{impostor, tcp}
	sawPinnedDial := false
	for range 16 {
		before, dialedBefore := pinnedDials(), dialed.Load()
		_ = fetch(t, c, epoch)
		if pinnedDials() > before {
			sawPinnedDial = true
			require.Equal(t, dialedBefore, dialed.Load(), "a pin mismatch on quic fell back to an unpinned tcp dial of the same authority")
		}
	}
	require.True(t, sawPinnedDial)
}
