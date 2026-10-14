// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func latencyPercentiles(durations []time.Duration) (median, p95 time.Duration) {
	sorted := slices.Sorted(slices.Values(durations))
	median = sorted[len(sorted)/2]
	p95 = sorted[(len(sorted)*95+99)/100-1]
	return median, p95
}

func TestLatencyPercentiles(t *testing.T) {
	for _, n := range []int{1, 20, 100} {
		durations := make([]time.Duration, n)
		for i := range durations {
			durations[i] = time.Duration(n-i) * time.Millisecond
		}
		median, p95 := latencyPercentiles(durations)
		require.Equal(t, time.Duration(n/2+1)*time.Millisecond, median, n)
		require.Equal(t, time.Duration((n*95+99)/100)*time.Millisecond, p95, n)
	}
}
