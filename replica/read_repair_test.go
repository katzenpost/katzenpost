// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/pigeonhole"
)

func TestBuildRepairWrite(t *testing.T) {
	t.Parallel()

	readReply := &pigeonhole.ReplicaReadReply{
		ErrorCode: pigeonhole.ReplicaSuccess,
		Payload:   []byte("box payload"),
	}
	readReply.BoxID[0] = 0xaa
	readReply.Signature[0] = 0xbb

	w := buildRepairWrite(readReply, nil)
	require.Equal(t, readReply.BoxID[:], w.BoxID[:])
	require.Equal(t, readReply.Signature[:], w.Signature[:])
	require.Equal(t, readReply.Payload, w.Payload)
}
