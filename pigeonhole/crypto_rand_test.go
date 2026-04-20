// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonhole

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCryptoRandIndexRange verifies the helper returns values strictly
// in [0, n) and never produces a negative result.
func TestCryptoRandIndexRange(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 7, 16, 64, 255, 256, 1000} {
		for i := 0; i < 200; i++ {
			v, err := cryptoRandIndex(n)
			require.NoError(t, err, "n=%d iter=%d", n, i)
			require.GreaterOrEqual(t, v, 0, "n=%d iter=%d value=%d", n, i, v)
			require.Less(t, v, n, "n=%d iter=%d value=%d", n, i, v)
		}
	}
}

// TestCryptoRandIndexRejectsNonPositive ensures the helper refuses
// nonsensical bounds rather than returning arbitrary values.
func TestCryptoRandIndexRejectsNonPositive(t *testing.T) {
	for _, n := range []int{0, -1, -100} {
		_, err := cryptoRandIndex(n)
		require.Error(t, err, "n=%d must error", n)
	}
}

// TestCryptoRandIndexConcurrentUsage hammers the helper from many
// goroutines to catch any shared-state hazards. The pre-fix
// package-global secureRand (*math/rand.Rand) was not documented as
// goroutine-safe; this test pins the post-fix invariant under -race.
func TestCryptoRandIndexConcurrentUsage(t *testing.T) {
	const (
		goroutines = 64
		perWorker  = 200
		n          = 17
	)

	var wg sync.WaitGroup
	var outOfRange atomic.Int32
	var errors atomic.Int32

	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < perWorker; j++ {
				v, err := cryptoRandIndex(n)
				if err != nil {
					errors.Add(1)
					continue
				}
				if v < 0 || v >= n {
					outOfRange.Add(1)
				}
			}
		}()
	}
	close(start)
	wg.Wait()

	require.Zero(t, errors.Load(), "no errors expected")
	require.Zero(t, outOfRange.Load(), "every concurrent draw must be in [0, %d)", n)
}

// TestCryptoRandIndexDistribution sanity-checks that the helper is not
// stuck in a corner of the range. For n=4 and 2000 draws the count of
// any bucket should land well away from 0 and 2000.
func TestCryptoRandIndexDistribution(t *testing.T) {
	const (
		n     = 4
		draws = 2000
	)
	var counts [n]int
	for i := 0; i < draws; i++ {
		v, err := cryptoRandIndex(n)
		require.NoError(t, err)
		counts[v]++
	}
	for i, c := range counts {
		require.Greater(t, c, draws/(n*4), "bucket %d underfull: %d", i, c)
		require.Less(t, c, draws, "bucket %d everything: %d", i, c)
	}
}
