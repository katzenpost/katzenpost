// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/quic/common"
)

type epochClock struct{ epoch uint64 }

func (c *epochClock) now() uint64 { return c.epoch }

func TestConsensusPinFollowsTheRotatedQUICKey(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	clock := &epochClock{epoch: epoch + 3}
	a := newQUICAuthorityKeys(t)
	keys, err := common.NewEpochKeys(t.TempDir(), clock.now)
	require.NoError(t, err)
	published, err := keys.Hashes(epoch + 3)
	require.NoError(t, err)
	addr := a.serve(t, keys, a.consensus(t, epoch, published))

	logFile := filepath.Join(t.TempDir(), "client.log")
	c, peer := a.client(t, logFile)
	peer.Addresses = []string{addr}
	require.NoError(t, fetch(t, c, epoch), "unpinned bootstrap")
	require.NoError(t, fetch(t, c, epoch), "consensus-pinned dial")
	logged, err := os.ReadFile(logFile)
	require.NoError(t, err)
	require.Contains(t, string(logged), "peer auth1: quic dial pinned to 3 consensus QUIC key hashes")
}
