// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/pki"
)

func TestQUICPinMismatchesForgetAMismatchAtTheNextEpoch(t *testing.T) {
	var a, b [pki.PublicKeyHashSize]byte
	a[0], b[0] = 1, 2
	var pins quicPinMismatches
	require.False(t, pins.has(a, 5))
	pins.mark(a, 5)
	require.True(t, pins.has(a, 5))
	require.False(t, pins.has(b, 5))
	require.False(t, pins.has(a, 6))
	pins.mark(b, 6)
	require.True(t, pins.has(b, 6))
	require.False(t, pins.has(a, 5))
	require.Len(t, pins.mismatched, 1)
}
