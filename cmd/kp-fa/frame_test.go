// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright (C) 2026 Jacob Appelbaum

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFrameRoundTrip(t *testing.T) {
	for _, f := range []frame{
		{kind: kindHeader, sync: noSync, body: []byte("head")},
		{kind: kindData, sync: 0, body: []byte("OggS")},
		{kind: kindData, sync: 3, body: []byte("tailOggS")},
		{kind: kindData, sync: noSync, body: []byte("continued")},
		{kind: kindEnd, sync: noSync, body: []byte{}},
	} {
		b := f.marshal()
		require.Len(t, b, frameOverhead+len(f.body))
		g, err := unmarshalFrame(b)
		require.NoError(t, err)
		require.Equal(t, f, g)
	}
}

func TestFrameWire(t *testing.T) {
	b := frame{kind: kindData, sync: 0x0102, body: []byte{9, 9, 9}}.marshal()
	require.Equal(t, []byte{frameVersion, kindData, 1, 2, 9, 9, 9}, b)
}

func TestUnmarshalFrameRejects(t *testing.T) {
	for name, b := range map[string][]byte{
		"empty":     nil,
		"short":     {frameVersion, kindData, 0},
		"version":   {frameVersion + 1, kindData, 0xff, 0xff},
		"kind":      {frameVersion, kindEnd + 1, 0xff, 0xff},
		"sync":      {frameVersion, kindData, 0, 1, 7},
		"syncEmpty": {frameVersion, kindData, 0, 0},
	} {
		_, err := unmarshalFrame(b)
		require.Error(t, err, name)
	}
}

func TestHeaderBody(t *testing.T) {
	init := []byte("OggS-init")
	codec, got, err := parseHeaderBody(headerBody(codecOpus, init))
	require.NoError(t, err)
	require.Equal(t, codecOpus, codec)
	require.Equal(t, init, got)
	for _, b := range [][]byte{nil, {5, 'a'}} {
		_, _, err := parseHeaderBody(b)
		require.Error(t, err)
	}
}
