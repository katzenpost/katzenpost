// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEpochMismatch(t *testing.T) {
	w := newTestWorkerBase()

	// Cold start: no documents, never a mismatch.
	_, haveAny, mismatched := w.epochMismatch(500)
	require.False(t, haveAny)
	require.False(t, mismatched)

	w.docs[500] = &Document{Epoch: 500}

	// Within the one-epoch window: fine.
	for _, clock := range []uint64{499, 500, 501} {
		latest, haveAny, mismatched := w.epochMismatch(clock)
		require.True(t, haveAny)
		require.Equal(t, uint64(500), latest)
		require.False(t, mismatched, "clock %d should be within window", clock)
	}

	// Two or more epochs behind or ahead of the clock: mismatch.
	for _, clock := range []uint64{498, 502, 560} {
		_, _, mismatched := w.epochMismatch(clock)
		require.True(t, mismatched, "clock %d should be flagged", clock)
	}
}
