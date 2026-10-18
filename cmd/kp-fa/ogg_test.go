// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright (C) 2026 Jacob Appelbaum

package main

import (
	"bytes"
	"io"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/require"
)

func oggPage(fill byte, lacing ...byte) []byte {
	p := []byte("OggS")
	p = append(p, make([]byte, oggHeaderLen-5)...)
	p = append(p, byte(len(lacing)))
	p = append(p, lacing...)
	n := 0
	for _, l := range lacing {
		n += int(l)
	}
	return append(p, bytes.Repeat([]byte{fill}, n)...)
}

func TestReadPage(t *testing.T) {
	a, b := oggPage('a', 19), oggPage('b', 255, 255, 3)
	r := iotest.OneByteReader(bytes.NewReader(append(append([]byte{}, a...), b...)))
	got, err := readPage(r)
	require.NoError(t, err)
	require.Equal(t, a, got)
	got, err = readPage(r)
	require.NoError(t, err)
	require.Equal(t, b, got)
	_, err = readPage(r)
	require.ErrorIs(t, err, io.EOF)
}

func TestReadPageRejects(t *testing.T) {
	p := oggPage('a', 40)
	for n := 1; n < len(p); n++ {
		_, err := readPage(bytes.NewReader(p[:n]))
		require.ErrorIs(t, err, io.ErrUnexpectedEOF, n)
	}
	bad := append([]byte{}, p...)
	bad[0] = 'P'
	_, err := readPage(bytes.NewReader(bad))
	require.ErrorIs(t, err, errNotOgg)
	bad = append([]byte{}, p...)
	bad[4] = 1
	_, err = readPage(bytes.NewReader(bad))
	require.ErrorIs(t, err, errNotOgg)
}

func TestReadInit(t *testing.T) {
	head := oggPage('h', 19)
	tags1 := oggPage('t', 255, 255)
	tags2 := oggPage('t', 255, 10)
	audio := oggPage('o', 80, 80)
	var in []byte
	for _, p := range [][]byte{head, tags1, tags2, audio} {
		in = append(in, p...)
	}
	r := bytes.NewReader(in)
	init, err := readInit(r)
	require.NoError(t, err)
	require.Equal(t, in[:len(head)+len(tags1)+len(tags2)], init)
	next, err := readPage(r)
	require.NoError(t, err)
	require.Equal(t, audio, next)
}

func TestReadInitTruncated(t *testing.T) {
	for _, in := range [][]byte{nil, oggPage('h', 19), append(oggPage('h', 19), oggPage('t', 255)...)} {
		_, err := readInit(bytes.NewReader(in))
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	}
}
