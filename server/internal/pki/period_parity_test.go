// SPDX-License-Identifier: AGPL-3.0-only

package pki

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
			{"recheckInterval", recheckInterval(), 75 * time.Second, 7500 * time.Millisecond},
			{"pkiEarlyConnectSlack", pkiEarlyConnectSlack(), 150 * time.Second, 15 * time.Second},
			{"PublishDeadline", PublishDeadline(), 150 * time.Second, 15 * time.Second},
			{"nextFetchTill", nextFetchTill(), 1050 * time.Second, 105 * time.Second},
			{"descriptorUploadSafety", descriptorUploadSafety(), 25 * time.Second, 2500 * time.Millisecond},
			{"descriptorRepostInterval", descriptorRepostInterval(), 12500 * time.Millisecond, 1250 * time.Millisecond},
		} {
			want := c.short
			if long {
				want = c.long
			}
			require.Equal(t, want, c.got, c.name)
		}
	})
}
