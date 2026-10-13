// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthorityQUICKeyPinsCoverTheirEpochs(t *testing.T) {
	var a, b [PublicKeyHashSize]byte
	a[0], b[0] = 1, 2
	h := make([]byte, 3*QUICKeyHashSize)
	h[0] = 7
	doc := &Document{Epoch: 100, AuthorityQUICKeyHashes: map[[PublicKeyHashSize]byte][]byte{a: h}}
	var pins AuthorityQUICKeyPins
	require.Nil(t, pins.Pins(a, 100), "pins before any consensus")
	pins.Learn(doc)
	h[0] = 8
	doc.AuthorityQUICKeyHashes[a][1] = 9
	for _, now := range []uint64{99, 100, 101} {
		got := pins.Pins(a, now)
		require.Len(t, got, 3*QUICKeyHashSize, "epoch %d", now)
		require.Equal(t, byte(7), got[0], "a learned pin aliases the document")
		require.Equal(t, byte(0), got[1], "a learned pin aliases the document")
		require.Nil(t, pins.Pins(b, now), "an authority the consensus does not name is pinned")
	}
	require.Nil(t, pins.Pins(a, 98), "a pin is used before the epochs it covers")
	require.Nil(t, pins.Pins(a, 102), "a pin outlived the epochs it covers")
	require.Nil(t, pins.Pins(a, 100), "an expired pin came back")
}

func TestAuthorityQUICKeyPinsJoinOverlappingConsensuses(t *testing.T) {
	var a [PublicKeyHashSize]byte
	var pins AuthorityQUICKeyPins
	for epoch := uint64(100); epoch <= 102; epoch++ {
		h := make([]byte, 3*QUICKeyHashSize)
		h[0] = byte(epoch)
		pins.Learn(&Document{Epoch: epoch, AuthorityQUICKeyHashes: map[[PublicKeyHashSize]byte][]byte{a: h}})
	}
	pins.Learn(&Document{Epoch: 103})
	got := pins.Pins(a, 101)
	require.Len(t, got, 9*QUICKeyHashSize)
	require.Equal(t, []byte{100, 101, 102}, []byte{got[0], got[3*QUICKeyHashSize], got[6*QUICKeyHashSize]})
	require.Len(t, pins.Pins(a, 103), 3*QUICKeyHashSize)
}
