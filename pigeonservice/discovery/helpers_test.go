// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package discovery_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/discovery"
)

func handle(t *testing.T, f *fixture, req *discovery.DirectoryRequest) *discovery.DirectoryReply {
	t.Helper()
	payload, err := common.Marshal(req)
	require.NoError(t, err)
	var reply discovery.DirectoryReply
	require.NoError(t, common.Unmarshal(f.dir.Handle(payload), &reply))
	return &reply
}

func snapshotPos(t *testing.T, r *discovery.DirectoryReply) (*bacap.ReadCap, *bacap.MessageBoxIndex) {
	t.Helper()
	rc, err := bacap.ReadCapFromBytes(r.ReadCap)
	require.NoError(t, err)
	idx, err := bacap.NewEmptyMessageBoxIndexFromBytes(r.StartIndex)
	require.NoError(t, err)
	return rc, idx
}
