// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// A newer replica may send command types this build does not handle;
// the session must survive them.
func TestHandleCommandToleratesUnknown(t *testing.T) {
	t.Parallel()

	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	c := &outgoingConn{
		log: backendLog.GetLogger("test"),
		dst: &cpki.ReplicaDescriptor{Name: "storagereplica9"},
	}

	unknown := &commands.ReplicaWrite{}
	require.True(t, c.handleCommand(unknown))
	require.True(t, c.handleCommand(unknown))
	require.True(t, c.unknownCmdSeen["*commands.ReplicaWrite"])

	require.False(t, c.handleCommand(&commands.Disconnect{}))
}
