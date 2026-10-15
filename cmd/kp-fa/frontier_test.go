// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright (C) 2026 Jacob Appelbaum

package main

import (
	"errors"
	"math/bits"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindFrontier(t *testing.T) {
	for _, n := range []uint64{0, 1, 2, 3, 7, 8, 9, 1000, 1 << 20} {
		probes := 0
		got, err := findFrontier(func(k uint64) (bool, error) {
			probes++
			return k <= n, nil
		})
		require.NoError(t, err)
		require.Equal(t, n, got)
		require.LessOrEqual(t, probes, 2*bits.Len64(n)+1, n)
	}
}

func TestFindFrontierHole(t *testing.T) {
	present := func(k uint64) bool { return k <= 100 && k != 50 }
	got, err := findFrontier(func(k uint64) (bool, error) { return present(k), nil })
	require.NoError(t, err)
	require.True(t, present(got))
	require.Equal(t, uint64(100), got)
}

func TestFindFrontierError(t *testing.T) {
	boom := errors.New("boom")
	_, err := findFrontier(func(k uint64) (bool, error) {
		if k == 8 {
			return false, boom
		}
		return true, nil
	})
	require.ErrorIs(t, err, boom)
}

func TestStartBox(t *testing.T) {
	require.Equal(t, uint64(1), startBox(0, 0, false, false))
	require.Equal(t, uint64(42), startBox(42, 0, false, false))
	require.Equal(t, uint64(40), startBox(42, 2, false, false))
	require.Equal(t, uint64(1), startBox(42, 41, false, false))
	require.Equal(t, uint64(1), startBox(42, 42, false, false))
	require.Equal(t, uint64(1), startBox(42, 1000, false, false))
	require.Equal(t, uint64(1), startBox(42, 0, true, false))
}

func TestStartBoxEnded(t *testing.T) {
	require.Equal(t, uint64(1), startBox(42, 0, false, true))
	require.Equal(t, uint64(40), startBox(42, 2, false, true))
	require.Equal(t, uint64(1), startBox(42, 50, false, true))
	require.Equal(t, uint64(1), startBox(0, 0, false, true))
}
