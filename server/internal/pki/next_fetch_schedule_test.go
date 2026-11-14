// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime/periodtest"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func TestNextDocumentIsNotRequestedBeforePublication(t *testing.T) {
	periodtest.Run(t, func(t *testing.T, p time.Duration) {
		requestsNext := func(elapsed time.Duration) bool { return p-elapsed < nextFetchTill() }
		for _, elapsed := range []time.Duration{0, p / 8, p/8 + time.Second, 4 * p / 8, cpki.PublishConsensusDeadline()} {
			require.False(t, requestsNext(elapsed), "elapsed %v", elapsed)
		}
		for _, elapsed := range []time.Duration{cpki.PublishConsensusDeadline() + time.Second, 7 * p / 8, p - time.Second} {
			require.True(t, requestsNext(elapsed), "elapsed %v", elapsed)
		}
	})
}
