// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// With no PKI document reachable, the description still renders replica
// IDs and per-slot reply state so an operator can see which shard was
// silent versus erroring.
func TestDescribeIntermediaries(t *testing.T) {
	t.Parallel()

	e := &Courier{server: &Server{}}
	entry := &CourierBookKeeping{
		IntermediateReplicas: [2]uint8{1, 3},
		EnvelopeReplies: [2]*commands.ReplicaMessageReply{
			{ErrorCode: 9},
			nil,
		},
	}
	got := e.describeIntermediaries(entry)
	require.Equal(t, "replicaID=1(err=9), replicaID=3(silent)", got)
}
