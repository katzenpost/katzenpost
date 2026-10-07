// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	vServer "github.com/katzenpost/katzenpost/authority/voting/server"
	"github.com/katzenpost/katzenpost/core/epochtime/periodtest"
)

func TestNextDocumentIsNotRequestedBeforePublication(t *testing.T) {
	periodtest.Run(t, func(t *testing.T, p time.Duration) {
		requestsNext := func(elapsed time.Duration) bool { return p-elapsed < nextFetchTill() }
		for _, elapsed := range []time.Duration{0, p / 8, p/8 + time.Second, 4 * p / 8, vServer.PublishConsensusDeadline()} {
			require.False(t, requestsNext(elapsed), "elapsed %v", elapsed)
		}
		for _, elapsed := range []time.Duration{vServer.PublishConsensusDeadline() + time.Second, 7 * p / 8, p - time.Second} {
			require.True(t, requestsNext(elapsed), "elapsed %v", elapsed)
		}
	})
}
