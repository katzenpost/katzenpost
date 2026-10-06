// SPDX-License-Identifier: AGPL-3.0-only

package epochtime_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/epochtime/periodtest"
)

func TestEpochArithmeticParity(t *testing.T) {
	periodtest.Run(t, func(t *testing.T, p time.Duration) {
		start := map[time.Duration]int64{
			20 * time.Minute: 1496275200 + 1000*1200,
			2 * time.Minute:  1496275200 + 1000*120,
		}[p]
		into := map[time.Duration]int64{20 * time.Minute: 420, 2 * time.Minute: 42}[p]
		length := map[time.Duration]int64{20 * time.Minute: 1200, 2 * time.Minute: 120}[p]

		e, elapsed, till := epochtime.FromUnix(start + into)
		require.Equal(t, uint64(1000), e)
		require.Equal(t, time.Duration(into)*time.Second, elapsed)
		require.Equal(t, time.Duration(length-into)*time.Second, till)

		e, elapsed, till = epochtime.FromUnix(start)
		require.Equal(t, uint64(1000), e)
		require.Equal(t, time.Duration(0), elapsed)
		require.Equal(t, time.Duration(length)*time.Second, till)

		require.True(t, epochtime.IsInEpoch(1000, uint64(start)))
		require.True(t, epochtime.IsInEpoch(1000, uint64(start+length-1)))
		require.False(t, epochtime.IsInEpoch(1000, uint64(start+length)))
		require.False(t, epochtime.IsInEpoch(999, uint64(start)))
		require.Equal(t, time.Date(2017, 6, 1, 0, 0, 0, 0, time.UTC), epochtime.Epoch)
	})
}

func TestWeekOfEpochsAtDefaultParity(t *testing.T) {
	if epochtime.Period() != 20*time.Minute {
		t.Skip("period is not the default")
	}
	require.Equal(t, uint64(504), epochtime.WeekOfEpochs)
}
