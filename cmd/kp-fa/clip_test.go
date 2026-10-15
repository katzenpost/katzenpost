// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright (C) 2026 Jacob Appelbaum

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const clipPath = "testdata/poacher-e03-3s.opus"

func readClip(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(clipPath)
	require.NoError(t, err)
	return b
}

func oggPages(t *testing.T, b []byte) [][]byte {
	t.Helper()
	var pages [][]byte
	r := bytes.NewReader(b)
	for {
		p, err := readPage(r)
		if errors.Is(err, io.EOF) {
			return pages
		}
		require.NoError(t, err)
		pages = append(pages, p)
	}
}

func pageBody(p []byte) []byte {
	return p[oggHeaderLen+int(p[26]):]
}

func sendClip(t *testing.T, clip []byte, maxPlaintext int) *memStore {
	t.Helper()
	var m memStore
	require.NoError(t, send(bytes.NewReader(clip), maxPlaintext, 3, m.write, func() {}))
	return &m
}

func TestClipRoundTrip(t *testing.T) {
	clip := readClip(t)
	for _, size := range []int{1500, 256} {
		m := sendClip(t, clip, size)
		h, err := unmarshalFrame(m.boxes[0])
		require.NoError(t, err)
		_, init, err := parseHeaderBody(h.body)
		require.NoError(t, err)
		var out bytes.Buffer
		require.NoError(t, play(&out, init, m.next(1)))
		require.Equal(t, clip, out.Bytes(), size)
	}
}

func TestClipHeaderBox(t *testing.T) {
	clip := readClip(t)
	m := sendClip(t, clip, 1500)
	h, err := unmarshalFrame(m.boxes[0])
	require.NoError(t, err)
	require.Equal(t, kindHeader, h.kind)
	codec, init, err := parseHeaderBody(h.body)
	require.NoError(t, err)
	require.Equal(t, codecOpus, codec)
	require.True(t, bytes.HasPrefix(clip, init))
	pages := oggPages(t, init)
	require.Len(t, pages, 2)
	require.True(t, bytes.HasPrefix(pageBody(pages[0]), []byte("OpusHead")))
	require.True(t, bytes.HasPrefix(pageBody(pages[1]), []byte("OpusTags")))
	rest := oggPages(t, clip[len(init):])
	require.NotEmpty(t, rest)
	require.False(t, bytes.HasPrefix(pageBody(rest[0]), []byte("Opus")))
}

func TestClipJoinOnPageBoundary(t *testing.T) {
	clip := readClip(t)
	m := sendClip(t, clip, 256)
	h, err := unmarshalFrame(m.boxes[0])
	require.NoError(t, err)
	_, init, err := parseHeaderBody(h.body)
	require.NoError(t, err)
	joined := 0
	for k := uint64(2); k < uint64(len(m.boxes)-1); k++ {
		var out bytes.Buffer
		require.NoError(t, play(&out, init, m.next(k)))
		got := out.Bytes()
		require.True(t, bytes.HasPrefix(got, init), k)
		rest := got[len(init):]
		if len(rest) == 0 {
			continue
		}
		require.True(t, bytes.HasPrefix(rest, []byte("OggS")), k)
		require.True(t, bytes.HasSuffix(clip, rest), k)
		require.NotEmpty(t, oggPages(t, got), k)
		joined++
	}
	require.Greater(t, joined, 5)
}
