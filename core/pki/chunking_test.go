// SPDX-FileCopyrightText: (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"
)

func TestChunkingSimple(t *testing.T) {
	payload1 := make([]byte, 1200)
	_, err := rand.Reader.Read(payload1)
	require.NoError(t, err)

	chunkSize := 4000
	chunks, err := Chunk(payload1, chunkSize)
	require.NoError(t, err)

	total := len(chunks)
	require.Equal(t, 1, total)

	dechunker := Dechunker{
		ChunkNum:   0,
		ChunkTotal: total,
		Chunks:     new(bytes.Buffer),
		Output:     nil,
	}

	for i := 0; i < len(chunks); i++ {
		err = dechunker.Consume(chunks[i], i, total)
		require.NoError(t, err)
	}

	payload2 := dechunker.Output
	require.Equal(t, payload1, payload2)
}

func TestChunking(t *testing.T) {
	payload1 := make([]byte, 1200)
	_, err := rand.Reader.Read(payload1)
	require.NoError(t, err)

	chunkSize := 179
	chunks, err := Chunk(payload1, chunkSize)
	require.NoError(t, err)

	total := len(chunks)

	dechunker := Dechunker{
		ChunkNum:   0,
		ChunkTotal: total,
		Chunks:     new(bytes.Buffer),
		Output:     nil,
	}

	for i := 0; i < len(chunks); i++ {
		err = dechunker.Consume(chunks[i], i, total)
		require.NoError(t, err)
	}

	payload2 := dechunker.Output
	require.Equal(t, payload1, payload2)
}
