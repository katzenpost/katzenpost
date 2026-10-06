// SPDX-License-Identifier: AGPL-3.0-only

package replica

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
			{"PublishDeadline", PublishDeadline(), 150 * time.Second, 15 * time.Second},
			{"descriptorUploadSafety", descriptorUploadSafety(), 25 * time.Second, 2500 * time.Millisecond},
			{"retryTTL", retryTTL(), 60 * time.Minute, 6 * time.Minute},
		} {
			want := c.short
			if long {
				want = c.long
			}
			require.Equal(t, want, c.got, c.name)
		}
	})
}
