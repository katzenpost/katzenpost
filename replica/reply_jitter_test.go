// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestReplyJitterFromLambdaR verifies that the reply-jitter bound is
// one mean link slot, J = 1/LambdaR, derived from the consensus rather
// than hardcoded.
func TestReplyJitterFromLambdaR(t *testing.T) {
	t.Parallel()

	// namenlos: LambdaR = 0.02 events/ms -> 50ms slots.
	j, err := replyJitterFromLambdaR(0.02)
	require.NoError(t, err)
	require.Equal(t, 50*time.Millisecond, j)

	// docker default: LambdaR = 0.005 events/ms -> 200ms slots.
	j, err = replyJitterFromLambdaR(0.005)
	require.NoError(t, err)
	require.Equal(t, 200*time.Millisecond, j)

	// Unusable rates are errors so callers fall back explicitly.
	_, err = replyJitterFromLambdaR(0)
	require.Error(t, err)
	_, err = replyJitterFromLambdaR(-1)
	require.Error(t, err)
}
