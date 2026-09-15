// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// A newer peer may send command types this build does not handle; the
// session must survive them on both the responder and initiator sides.
func TestOnReplicaCommandToleratesUnknown(t *testing.T) {
	t.Parallel()

	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	c := &incomingConn{log: backendLog.GetLogger("test")}

	req, ok := c.onReplicaCommand(&commands.ReplicaWriteReply{}, nil)
	require.Nil(t, req)
	require.True(t, ok)

	req, ok = c.onReplicaCommand(&commands.Disconnect{}, nil)
	require.Nil(t, req)
	require.False(t, ok)
}

func TestOutgoingWarnUnknownCommandDedup(t *testing.T) {
	t.Parallel()

	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	c := &outgoingConn{
		log: backendLog.GetLogger("test"),
		dst: &cpki.ReplicaDescriptor{Name: "storagereplica9"},
	}
	c.warnUnknownCommandOnce(&commands.ReplicaWrite{})
	c.warnUnknownCommandOnce(&commands.ReplicaWrite{})
	require.True(t, c.unknownCmdSeen["*commands.ReplicaWrite"])
	require.Len(t, c.unknownCmdSeen, 1)
}
