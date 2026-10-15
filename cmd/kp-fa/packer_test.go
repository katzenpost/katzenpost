// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright (C) 2026 Jacob Appelbaum

package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPackerSyncOffsets(t *testing.T) {
	p := newPacker(10)
	var raw [][]byte
	for i, n := range []int{4, 9, 3, 4, 20, 2} {
		raw = append(raw, p.add(bytes.Repeat([]byte{byte('a' + i)}, n))...)
	}
	raw = append(raw, p.flush())
	require.Nil(t, p.flush())
	want := []frame{
		{kindData, 0, []byte("aaaabbbbbb")},
		{kindData, 3, []byte("bbbcccdddd")},
		{kindData, 0, []byte("eeeeeeeeee")},
		{kindData, noSync, []byte("eeeeeeeeee")},
		{kindData, 0, []byte("ff")},
	}
	require.Len(t, raw, len(want))
	for i, b := range raw {
		f, err := unmarshalFrame(b)
		require.NoError(t, err)
		require.Equal(t, want[i], f, i)
	}
}
