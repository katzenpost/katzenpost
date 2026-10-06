// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime/periodtest"
)

func TestPeriodDerivedParity(t *testing.T) {
	periodtest.Run(t, func(t *testing.T, p time.Duration) {
		long := p == 20*time.Minute
		for _, c := range []struct {
			name        string
			got         time.Duration
			long, short time.Duration
		}{
			{"PublishDeadline", PublishDeadline, 750 * time.Second, 75 * time.Second},
			{"mixServerCacheDelay", mixServerCacheDelay, 75 * time.Second, 7500 * time.Millisecond},
			{"nextFetchTill", nextFetchTill, 375 * time.Second, 37500 * time.Millisecond},
			{"recheckInterval", recheckInterval, 75 * time.Second, 7500 * time.Millisecond},
		} {
			want := c.short
			if long {
				want = c.long
			}
			require.Equal(t, want, c.got, c.name)
		}
	})
}
