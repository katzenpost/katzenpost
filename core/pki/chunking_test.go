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

	err = dechunker.Consume(chunks[0], 0, 1)
	require.NoError(t, err)
	require.Equal(t, payload1, dechunker.Output)
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

func TestChunkingInvalidSize(t *testing.T) {
	payload := []byte("some payload data")
	_, err := Chunk(payload, 0)
	require.Error(t, err)

	_, err = Chunk(payload, -10)
	require.Error(t, err)

	d := NewDechunker()
	err = d.Consume(payload, -1, 1)
	require.Error(t, err)

	err = d.Consume(payload, 2, 1)
	require.Error(t, err)
}

func TestChunkingSequenceAndBounds(t *testing.T) {
	d := NewDechunker()
	// Chunk sequence must start at 0
	err := d.Consume([]byte("data"), 1, 2)
	require.Error(t, err)

	// Valid first chunk
	d = NewDechunker()
	err = d.Consume([]byte("data"), 0, 2)
	require.NoError(t, err)

	// Repeated chunk must be rejected
	err = d.Consume([]byte("data"), 0, 2)
	require.Error(t, err)

	// Total exceeding MaxChunks must be rejected
	d = NewDechunker()
	err = d.Consume([]byte("data"), 0, MaxChunks+1)
	require.Error(t, err)
}
