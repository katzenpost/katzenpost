// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

// A transiently-invalid peer (descriptor churn during staggered upgrades)
// must survive reauthGraceLimit-1 consecutive failures, die on the next,
// and a success in between must reset the count.
func TestReauthGrace(t *testing.T) {
	t.Parallel()

	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	c := &outgoingConn{
		log: backendLog.GetLogger("test"),
		dst: &cpki.ReplicaDescriptor{Name: "storagereplica9"},
	}

	require.True(t, c.reauthOutcome(false))
	require.True(t, c.reauthOutcome(false))
	require.False(t, c.reauthOutcome(false))

	c.reauthFailures = 0
	require.True(t, c.reauthOutcome(false))
	require.True(t, c.reauthOutcome(true))
	require.Equal(t, 0, c.reauthFailures)
	require.True(t, c.reauthOutcome(false))
	require.True(t, c.reauthOutcome(false))
	require.False(t, c.reauthOutcome(false))
}
