// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
)

func TestPhaseDeadlineKeepsAFiveSecondBuffer(t *testing.T) {
	savedEpoch := epochtime.Epoch
	t.Cleanup(func() { epochtime.Epoch = savedEpoch })
	elapsed := epochtime.Period() / 4
	epochtime.Epoch = time.Now().Add(-elapsed)
	s := new(state)
	for _, c := range []struct {
		target, want time.Duration
	}{
		{elapsed + time.Minute, time.Minute - 5*time.Second},
		{elapsed + 6*time.Second, time.Second},
		{elapsed + 5*time.Second, 5 * time.Second},
		{elapsed + 3*time.Second, 3 * time.Second},
		{elapsed, 0},
		{elapsed - time.Minute, 0},
	} {
		got := time.Until(s.phaseDeadline(c.target))
		require.InDelta(t, c.want, got, float64(500*time.Millisecond), "target %v", c.target)
	}
}
