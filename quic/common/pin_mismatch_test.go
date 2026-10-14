// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQUICPinMismatchesForgetAMismatchAtTheNextEpoch(t *testing.T) {
	var a, b [sha256.Size]byte
	a[0], b[0] = 1, 2
	var pins QUICPinMismatches
	require.False(t, pins.Has(a, 5))
	pins.Mark(a, 5)
	require.True(t, pins.Has(a, 5))
	require.False(t, pins.Has(b, 5))
	require.False(t, pins.Has(a, 6))
	pins.Mark(b, 6)
	require.True(t, pins.Has(b, 6))
	require.False(t, pins.Has(a, 5))
	require.Len(t, pins.peers, 1)
}

func TestAddressesAfterPinMismatch(t *testing.T) {
	addrs := []string{"tcp://192.0.2.1:1", "quic://192.0.2.1:2", "tcp4://192.0.2.1:3", "quic://192.0.2.1:4"}
	require.Equal(t, []string{"tcp://192.0.2.1:1", "tcp4://192.0.2.1:3"}, (*Options)(nil).AddressesAfterPinMismatch(addrs))
	require.Equal(t, []string{"tcp://192.0.2.1:1", "tcp4://192.0.2.1:3"}, (&Options{PinMismatch: PinMismatchFallback}).AddressesAfterPinMismatch(addrs))
	require.Equal(t, []string{"quic://192.0.2.1:2", "quic://192.0.2.1:4"}, (&Options{PinMismatch: PinMismatchStrict}).AddressesAfterPinMismatch(addrs))
	require.Len(t, addrs, 4)
}

func TestQUICPinMismatchesIgnoreAMarkForAnOlderEpoch(t *testing.T) {
	var p, q [sha256.Size]byte
	p[0], q[0] = 1, 2
	var pins QUICPinMismatches
	pins.Mark(p, 6)
	pins.Mark(q, 5)
	require.True(t, pins.Has(p, 6), "a mark for an older epoch wiped the current epoch's mismatches")
	require.False(t, pins.Has(q, 5))
}
