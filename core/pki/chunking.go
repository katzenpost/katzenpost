// SPDX-FileCopyrightText: (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
)

type Chunker struct {
	ChunkSize int
	Total     int
}

func Chunk(blob []byte, chunkSize int) ([][]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(blob)
	if err != nil {
		return nil, err
	}
	err = zw.Close()
	if err != nil {
		return nil, err
	}
	compressedRawDoc := buf.Bytes()
	docSize := len(compressedRawDoc)
	total := docSize / chunkSize
	size := chunkSize * total
	if size < docSize {
		total += 1
	}

	chunks := make([][]byte, 0, total)
	offset := 0
	for i := 0; i < total; i++ {
		var chunk []byte
		if i == (total - 1) {
			// last
			chunk = compressedRawDoc[offset:]
		} else {
			chunk = compressedRawDoc[offset : offset+chunkSize]
		}
		chunks = append(chunks, chunk)
		offset += chunkSize
	}
	return chunks, nil
}

type Dechunker struct {
	ChunkNum   int
	ChunkTotal int
	Chunks     *bytes.Buffer
	Output     []byte
}

func (d *Dechunker) Consume(payload []byte, num, total int) error {
	if d.ChunkNum != 0 {
		if int(total) != d.ChunkTotal {
			return errors.New("Receive invalid Consensus2.ChunkTotal")
		}
	}
	d.Chunks.Write(payload)
	if int(num) == (d.ChunkTotal - 1) {
		// last chunk
		zr, err := gzip.NewReader(d.Chunks)
		if err != nil {
			return err
		}
		var acc bytes.Buffer
		io.Copy(&acc, zr)
		d.Output = acc.Bytes()
	}
	return nil
}
