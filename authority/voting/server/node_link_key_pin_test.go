// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"

	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func (w *wireUploadFixture) holdSlots(t *testing.T, n int, keyFor func() kem.PrivateKey) {
	t.Helper()
	for i := 0; i < n; i++ {
		_, err := w.dial(t, keyFor())
		require.NoError(t, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		w.srv.peerSlotMu.Lock()
		held := w.srv.peerSlots[w.idHash]
		w.srv.peerSlotMu.Unlock()
		if held >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPinnedNodeCappedAtMaxConnsPerPeer(t *testing.T) {
	const perPeer = 2
	for _, kind := range []string{"mix", "replica"} {
		t.Run(kind, func(t *testing.T) {
			w := newWireUploadFixture(t, kind, perPeer)
			key, blob := w.newLinkKey(t)
			code, err := w.post(t, kind, key, w.epoch, blob)
			require.NoError(t, err)
			require.Equal(t, uint8(commands.DescriptorOk), code)

			w.holdSlots(t, perPeer, func() kem.PrivateKey { return key })
			_, err = w.post(t, kind, key, w.epoch, blob)
			require.Error(t, err, "pinned %s connection beyond MaxConnsPerPeer was served", kind)
		})
	}
}

func TestImpostorCannotConsumePinnedNodeSlots(t *testing.T) {
	const perPeer = 2
	for _, kind := range []string{"mix", "replica"} {
		t.Run(kind, func(t *testing.T) {
			w := newWireUploadFixture(t, kind, perPeer)
			key, blob := w.newLinkKey(t)
			code, err := w.post(t, kind, key, w.epoch, blob)
			require.NoError(t, err)
			require.Equal(t, uint8(commands.DescriptorOk), code)

			w.holdSlots(t, perPeer, func() kem.PrivateKey {
				impostor, _ := w.newLinkKey(t)
				return impostor
			})
			code, err = w.post(t, kind, key, w.epoch, blob)
			require.NoError(t, err, "genuine %s refused while an impostor holds connections under its identity", kind)
			require.Equal(t, uint8(commands.DescriptorOk), code)
		})
	}
}

func TestUnpinnedNodeFirstContactAndRotation(t *testing.T) {
	const perPeer = 2
	for _, kind := range []string{"mix", "replica"} {
		t.Run(kind, func(t *testing.T) {
			w := newWireUploadFixture(t, kind, perPeer)
			oldKey, oldBlob := w.newLinkKey(t)
			code, err := w.post(t, kind, oldKey, w.epoch, oldBlob)
			require.NoError(t, err, "first contact %s refused", kind)
			require.Equal(t, uint8(commands.DescriptorOk), code)

			newKey, newBlob := w.newLinkKey(t)
			code, err = w.post(t, kind, newKey, w.epoch+1, newBlob)
			require.NoError(t, err, "%s rotating its link key refused", kind)
			require.Equal(t, uint8(commands.DescriptorOk), code)

			code, err = w.post(t, kind, newKey, w.epoch+1, newBlob)
			require.NoError(t, err)
			require.Equal(t, uint8(commands.DescriptorOk), code)
			code, err = w.post(t, kind, oldKey, w.epoch, oldBlob)
			require.NoError(t, err)
			require.Equal(t, uint8(commands.DescriptorOk), code)
		})
	}
}
