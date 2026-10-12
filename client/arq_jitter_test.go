// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestARQResendAtJitter(t *testing.T) {
	sentAt := time.Unix(1700000000, 0)
	eta := 3 * time.Second
	lo := sentAt.Add(eta + RoundTripTimeSlop)
	hi := lo.Add(RoundTripTimeSlop)
	seen := make(map[time.Time]bool)
	for range 1000 {
		at := arqResendAt(sentAt, eta)
		require.False(t, at.Before(lo))
		require.False(t, at.After(hi))
		seen[at] = true
	}
	require.Greater(t, len(seen), 900)
}
