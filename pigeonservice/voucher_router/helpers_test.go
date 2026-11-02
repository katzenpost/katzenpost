// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package voucher_router_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/katzenpost/pigeonservice/voucher_router"
)

func readPos(t *testing.T, st *voucher_router.ConnState) (*bacap.ReadCap, *bacap.MessageBoxIndex) {
	t.Helper()
	rc, err := bacap.ReadCapFromBytes(st.ReadCap)
	require.NoError(t, err)
	idx, err := bacap.NewEmptyMessageBoxIndexFromBytes(st.ReadIdx)
	require.NoError(t, err)
	return rc, idx
}

// in is a lease expiry d from now.
func in(d time.Duration) uint64 { return uint64(time.Now().Add(d).Unix()) }
