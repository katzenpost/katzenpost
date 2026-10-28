// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonservice_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"

	ps "github.com/katzenpost/katzenpost/pigeonservice"
)

func readPos(t *testing.T, st *ps.ConnState) (*bacap.ReadCap, *bacap.MessageBoxIndex) {
	t.Helper()
	rc, err := bacap.ReadCapFromBytes(st.ReadCap)
	require.NoError(t, err)
	idx, err := bacap.NewEmptyMessageBoxIndexFromBytes(st.ReadIdx)
	require.NoError(t, err)
	return rc, idx
}
