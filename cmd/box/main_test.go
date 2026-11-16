// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/katzenpost/client/constants"
)

// The capabilities round trip through the hex that new-cap prints, and the
// read side of index n names the same box as the write side.
func TestCapHexAndIndexAgree(t *testing.T) {
	w, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	wb, err := w.MarshalBinary()
	require.NoError(t, err)
	rb, err := w.ReadCap().MarshalBinary()
	require.NoError(t, err)

	w2, err := bacap.NewWriteCapFromBytes(mustHex(t, hex.EncodeToString(wb)))
	require.NoError(t, err)
	r2 := bacap.NewEmptyReadCap()
	require.NoError(t, r2.UnmarshalBinary(mustHex(t, hex.EncodeToString(rb))))

	for _, n := range []uint64{0, 1, 7} {
		wp := w2.Start()
		rp := r2.Start()
		if n > 0 {
			wp, err = wp.AdvanceTo(wp.Index().Idx64 + n)
			require.NoError(t, err)
			rp, err = rp.AdvanceTo(rp.Index().Idx64 + n)
			require.NoError(t, err)
		}
		wid, err := wp.BoxID(constants.PIGEONHOLE_CTX)
		require.NoError(t, err)
		rid, err := rp.BoxID(constants.PIGEONHOLE_CTX)
		require.NoError(t, err)
		require.Equal(t, wid.Bytes(), rid.Bytes(), "index %d", n)
	}
}

func mustHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}
