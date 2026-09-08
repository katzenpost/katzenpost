// SPDX-FileCopyrightText: © 2026 Jacob Appelbaum
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestClampSleep is the regression for the FSM scheduling a negative sleep:
// when a phase deadline has already passed (clock skew or slow processing),
// deadline-nowelapsed is negative, and the FSM must not hand a negative
// duration to time.After. clampSleep floors it at zero.
func TestClampSleep(t *testing.T) {
	require.Equal(t, time.Duration(0), clampSleep(-5*time.Second))
	require.Equal(t, time.Duration(0), clampSleep(0))
	require.Equal(t, 3*time.Second, clampSleep(3*time.Second))
}
