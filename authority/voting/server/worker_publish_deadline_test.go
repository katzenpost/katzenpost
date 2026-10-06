// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime/periodtest"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func TestWorkerPublishDeadlineIsTheAuthoritys(t *testing.T) {
	periodtest.Run(t, func(t *testing.T, p time.Duration) {
		require.Equal(t, PublishConsensusDeadline(), cpki.PublishConsensusDeadline())
	})
}
