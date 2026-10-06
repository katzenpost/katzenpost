// SPDX-FileCopyrightText: (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"
)

const testConsensusCeiling = 1 << 20

func TestChunkingSimple(t *testing.T) {
	payload1 := make([]byte, 1200)
	_, err := rand.Reader.Read(payload1)
	require.NoError(t, err)

	chunkSize := 4000
	chunks, err := Chunk(payload1, chunkSize)
	require.NoError(t, err)

	total := len(chunks)
	require.Equal(t, 1, total)

	dechunker := NewDechunker(testConsensusCeiling)

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

	dechunker := NewDechunker(testConsensusCeiling)

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

	d := NewDechunker(testConsensusCeiling)
	err = d.Consume(payload, -1, 1)
	require.Error(t, err)

	err = d.Consume(payload, 2, 1)
	require.Error(t, err)
}

func TestChunkingSequenceAndBounds(t *testing.T) {
	d := NewDechunker(testConsensusCeiling)
	// Chunk sequence must start at 0
	err := d.Consume([]byte("data"), 1, 2)
	require.Error(t, err)

	// Valid first chunk
	d = NewDechunker(testConsensusCeiling)
	err = d.Consume([]byte("data"), 0, 2)
	require.NoError(t, err)

	// Repeated chunk must be rejected
	err = d.Consume([]byte("data"), 0, 2)
	require.Error(t, err)

	d = NewDechunker(4)
	err = d.Consume([]byte("data"), 0, 5)
	require.Error(t, err)

	d = NewDechunker(4)
	err = d.Consume([]byte("data"), 0, 4)
	require.NoError(t, err)
}

func consumeAll(d *Dechunker, chunks [][]byte) (int, error) {
	for i, chunk := range chunks {
		if err := d.Consume(chunk, i, len(chunks)); err != nil {
			return i, err
		}
	}
	return len(chunks), nil
}

func TestDechunkerAcceptsConsensusAtCeiling(t *testing.T) {
	const ceiling = 64 * 1024
	doc := bytes.Repeat([]byte("consensus "), ceiling/10)
	doc = append(doc, make([]byte, ceiling-len(doc))...)
	chunks, err := Chunk(doc, 512)
	require.NoError(t, err)

	d := NewDechunker(ceiling)
	consumed, err := consumeAll(d, chunks)
	require.NoError(t, err)
	require.Equal(t, len(chunks), consumed)
	require.Equal(t, doc, d.Output)
}

func TestDechunkerRejectsDecompressedOverCeiling(t *testing.T) {
	const ceiling = 64 * 1024
	chunks, err := Chunk(make([]byte, ceiling+1), 512)
	require.NoError(t, err)

	d := NewDechunker(ceiling)
	consumed, err := consumeAll(d, chunks)
	require.Error(t, err)
	require.Equal(t, len(chunks)-1, consumed)
	require.Empty(t, d.Output)
}

func TestDechunkerRejectsCompressedOverCeilingMidStream(t *testing.T) {
	const ceiling = 1024
	doc := make([]byte, 4*ceiling)
	_, err := rand.Reader.Read(doc)
	require.NoError(t, err)
	chunks, err := Chunk(doc, 256)
	require.NoError(t, err)

	d := NewDechunker(ceiling)
	consumed, err := consumeAll(d, chunks)
	require.Error(t, err)
	require.Equal(t, ceiling/256, consumed)
	require.Empty(t, d.Output)
}
