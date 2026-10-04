// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonhole

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/rand"
)

func TestOpenBox(t *testing.T) {
	ctx := []byte("pigeonhole context")
	wc, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	rc := wc.ReadCap()
	here := wc.GetMessageBoxIndex()
	there, err := here.NextIndex()
	require.NoError(t, err)

	box, ct, sig, err := here.EncryptForContext(wc, ctx, []byte("hello"))
	require.NoError(t, err)
	pt, err := OpenBox(rc, here, ctx, box, ct, sig)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)

	// A tombstone for the next box verifies under its own box ID and has
	// nothing to decrypt: DecryptForContext alone accepts it here.
	tbox, tsig, err := there.SignBox(wc, ctx, []byte{})
	require.NoError(t, err)
	_, err = here.DecryptForContext(tbox, ctx, []byte{}, tsig)
	require.NoError(t, err)
	_, err = OpenBox(rc, here, ctx, tbox, []byte{}, tsig)
	require.ErrorIs(t, err, ErrBoxMismatch)

	pt, err = OpenBox(rc, there, ctx, tbox, []byte{}, tsig)
	require.NoError(t, err)
	require.Empty(t, pt)

	var zero [bacap.BoxIDSize]byte
	_, err = OpenBox(rc, here, ctx, zero, ct, sig)
	require.ErrorIs(t, err, ErrEmptyBox)

	tampered := append([]byte{}, ct...)
	tampered[0] ^= 1
	_, err = OpenBox(rc, here, ctx, box, tampered, sig)
	require.Error(t, err)
}
