// SPDX-License-Identifier: AGPL-3.0-only

package server

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
			{"MixPublishDeadline", MixPublishDeadline(), 150 * time.Second, 15 * time.Second},
			{"AuthorityVoteDeadline", AuthorityVoteDeadline(), 300 * time.Second, 30 * time.Second},
			{"AuthorityRevealDeadline", AuthorityRevealDeadline(), 450 * time.Second, 45 * time.Second},
			{"AuthorityCertDeadline", AuthorityCertDeadline(), 600 * time.Second, 60 * time.Second},
			{"PublishConsensusDeadline", PublishConsensusDeadline(), 750 * time.Second, 75 * time.Second},
		} {
			want := c.short
			if long {
				want = c.long
			}
			require.Equal(t, want, c.got, c.name)
		}
	})
}
