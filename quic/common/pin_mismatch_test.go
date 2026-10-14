// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"bytes"
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

func TestPeerDialerDialable(t *testing.T) {
	var peer [sha256.Size]byte
	hashes := bytes.Repeat([]byte{1}, sha256.Size)
	for _, c := range []struct {
		opts      *Options
		tcp, quic bool
	}{
		{nil, true, false},
		{&Options{PinMismatch: PinMismatchFallback}, true, false},
		{&Options{PinMismatch: PinMismatchStrict}, false, true},
	} {
		var mismatches QUICPinMismatches
		d := c.opts.PeerDialer(&mismatches, peer, hashes, nil, "peer")
		require.True(t, d.Dialable("tcp://192.0.2.1:1"))
		require.True(t, d.Dialable("quic://192.0.2.1:2"))
		mismatches.Mark(peer, d.epoch)
		require.Equal(t, c.tcp, d.Dialable("tcp://192.0.2.1:1"))
		require.Equal(t, c.tcp, d.Dialable("onion://192.0.2.1:3"))
		require.Equal(t, c.quic, d.Dialable("quic://192.0.2.1:2"))
	}
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
