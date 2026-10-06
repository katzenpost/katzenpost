// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
)

func TestRecheckIntervalFollowsPeriod(t *testing.T) {
	require.Equal(t, epochtime.Period()/16, recheckInterval)
}
