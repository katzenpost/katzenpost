// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package directory_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"

	ps "github.com/katzenpost/katzenpost/pigeonservice"
)

func handle(t *testing.T, f *fixture, req *ps.DirectoryRequest) *ps.DirectoryReply {
	t.Helper()
	payload, err := ps.Marshal(req)
	require.NoError(t, err)
	var reply ps.DirectoryReply
	require.NoError(t, ps.Unmarshal(f.dir.Handle(payload), &reply))
	return &reply
}

func snapshotPos(t *testing.T, r *ps.DirectoryReply) (*bacap.ReadCap, *bacap.MessageBoxIndex) {
	t.Helper()
	rc, err := bacap.ReadCapFromBytes(r.ReadCap)
	require.NoError(t, err)
	idx, err := bacap.NewEmptyMessageBoxIndexFromBytes(r.StartIndex)
	require.NoError(t, err)
	return rc, idx
}
