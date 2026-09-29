// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

// Mirror of the courier's grace: survive reauthGraceLimit-1 consecutive
// failures, die on the next, reset on success.
func TestReplicaReauthGrace(t *testing.T) {
	t.Parallel()

	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	c := &outgoingConn{
		log: backendLog.GetLogger("test"),
		dst: &cpki.ReplicaDescriptor{Name: "storagereplica9"},
	}

	require.True(t, c.reauthOutcome(false))
	require.True(t, c.reauthOutcome(true))
	require.Equal(t, 0, c.reauthFailures)
	require.True(t, c.reauthOutcome(false))
	require.True(t, c.reauthOutcome(false))
	require.False(t, c.reauthOutcome(false))
}
