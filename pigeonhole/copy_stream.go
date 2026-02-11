// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package pigeonhole - copy stream encoding/decoding for Copy Channel API
package pigeonhole

import (
	"encoding/binary"
	"fmt"
)

// EncodeCopyStream encodes a list of CourierEnvelopes into a copy stream format.
//
// The format is a continuous byte stream where each CourierEnvelope is prefixed
// with its length (4 bytes, big-endian):
//
//	[4-byte length][CourierEnvelope bytes][4-byte length][CourierEnvelope bytes]...
//
// This format allows CourierEnvelopes to span multiple BACAP boxes when the
// stream is chunked for storage in the temporary copy channel.
//
// Parameters:
//   - envelopes: List of CourierEnvelope pointers to encode
//
// Returns:
//   - []byte: The encoded copy stream
//   - error: Any error encountered during encoding
//
// Example:
//
//	envelopes := []*CourierEnvelope{envelope1, envelope2, envelope3}
//	stream, err := EncodeCopyStream(envelopes)
//	if err != nil {
//	    log.Fatal("Failed to encode copy stream:", err)
//	}
func EncodeCopyStream(envelopes []*CourierEnvelope) ([]byte, error) {
	if len(envelopes) == 0 {
		return []byte{}, nil
	}

	var stream []byte

	for i, envelope := range envelopes {
		if envelope == nil {
			return nil, fmt.Errorf("envelope at index %d is nil", i)
		}

		// Serialize the CourierEnvelope using trunnel
		envelopeBytes, err := envelope.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal envelope at index %d: %w", i, err)
		}

		// Write 4-byte length prefix (big-endian)
		lengthPrefix := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthPrefix, uint32(len(envelopeBytes)))
		stream = append(stream, lengthPrefix...)

		// Write envelope bytes
		stream = append(stream, envelopeBytes...)
	}

	return stream, nil
}

// DecodeCopyStream decodes a copy stream into a list of CourierEnvelopes.
//
// The format is a continuous byte stream where each CourierEnvelope is prefixed
// with its length (4 bytes, big-endian):
//
//	[4-byte length][CourierEnvelope bytes][4-byte length][CourierEnvelope bytes]...
//
// This function parses the stream and extracts all CourierEnvelopes.
//
// Parameters:
//   - data: The encoded copy stream bytes
//
// Returns:
//   - []*CourierEnvelope: List of decoded CourierEnvelopes
//   - error: Any error encountered during decoding
//
// Example:
//
//	envelopes, err := DecodeCopyStream(streamBytes)
//	if err != nil {
//	    log.Fatal("Failed to decode copy stream:", err)
//	}
//	for i, envelope := range envelopes {
//	    log.Printf("Envelope %d: %d bytes", i, len(envelope.Ciphertext))
//	}
func DecodeCopyStream(data []byte) ([]*CourierEnvelope, error) {
	if len(data) == 0 {
		return []*CourierEnvelope{}, nil
	}

	var envelopes []*CourierEnvelope
	offset := 0

	for offset < len(data) {
		// Read 4-byte length prefix
		if offset+4 > len(data) {
			return nil, fmt.Errorf("incomplete length prefix at offset %d: need 4 bytes, have %d", offset, len(data)-offset)
		}

		length := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		// Validate length
		if length == 0 {
			return nil, fmt.Errorf("invalid zero-length envelope at offset %d", offset-4)
		}
		if length > 1024*1024 { // Sanity check: 1MB max per envelope
			return nil, fmt.Errorf("envelope length %d exceeds maximum (1MB) at offset %d", length, offset-4)
		}

		// Read envelope bytes
		if offset+int(length) > len(data) {
			return nil, fmt.Errorf("incomplete envelope at offset %d: need %d bytes, have %d", offset, length, len(data)-offset)
		}

		envelopeBytes := data[offset : offset+int(length)]
		offset += int(length)

		// Parse the CourierEnvelope using trunnel
		envelope := &CourierEnvelope{}
		remaining, err := envelope.Parse(envelopeBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse envelope at offset %d: %w", offset-int(length), err)
		}

		// Verify that all bytes were consumed
		if len(remaining) > 0 {
			return nil, fmt.Errorf("envelope at offset %d has %d trailing bytes", offset-int(length), len(remaining))
		}

		envelopes = append(envelopes, envelope)
	}

	return envelopes, nil
}

// CopyStreamDecoder is a streaming decoder for the copy stream format.
// It accumulates data from multiple boxes and emits complete CourierEnvelopes
// as they become available.
type CopyStreamDecoder struct {
	buffer []byte // Accumulated bytes from boxes
}

// NewCopyStreamDecoder creates a new streaming copy stream decoder.
func NewCopyStreamDecoder() *CopyStreamDecoder {
	return &CopyStreamDecoder{
		buffer: make([]byte, 0),
	}
}

// AddData adds data from a box to the decoder's buffer.
// Call this each time you read a new box from the copy stream channel.
func (d *CopyStreamDecoder) AddData(data []byte) {
	d.buffer = append(d.buffer, data...)
}

// DecodeAvailable attempts to decode all complete envelopes from the current buffer.
// Returns a slice of decoded envelopes and any error encountered.
// Incomplete envelopes remain in the buffer for the next call.
//
// This should be called after each AddData() to extract any complete envelopes.
func (d *CopyStreamDecoder) DecodeAvailable() ([]*CourierEnvelope, error) {
	var envelopes []*CourierEnvelope

	for len(d.buffer) >= 4 {
		// Read 4-byte length prefix
		length := uint32(d.buffer[0])<<24 | uint32(d.buffer[1])<<16 | uint32(d.buffer[2])<<8 | uint32(d.buffer[3])

		// Validate length
		if length == 0 {
			return nil, fmt.Errorf("invalid zero-length envelope at buffer offset 0")
		}
		if length > 1024*1024 { // Sanity check: 1MB max per envelope
			return nil, fmt.Errorf("envelope length %d exceeds maximum (1MB)", length)
		}

		// Check if we have the complete envelope
		if uint32(len(d.buffer)) < 4+length {
			// Need more data, stop processing
			break
		}

		// Extract envelope bytes
		envelopeBytes := d.buffer[4 : 4+length]

		// Parse the CourierEnvelope using trunnel
		envelope := &CourierEnvelope{}
		remaining, err := envelope.Parse(envelopeBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse envelope: %w", err)
		}

		// Verify that all bytes were consumed
		if len(remaining) > 0 {
			return nil, fmt.Errorf("envelope has %d trailing bytes", len(remaining))
		}

		envelopes = append(envelopes, envelope)

		// Remove processed envelope from buffer
		d.buffer = d.buffer[4+length:]
	}

	return envelopes, nil
}

// Remaining returns the number of bytes remaining in the buffer.
// This should be 0 after processing the last box (with stop marker).
func (d *CopyStreamDecoder) Remaining() int {
	return len(d.buffer)
}

// CopyStreamEncoder is a streaming encoder for the copy stream format.
// It accepts CourierEnvelopes incrementally and outputs box-sized chunks
// ready to be written to a BACAP channel.
type CopyStreamEncoder struct {
	buffer  []byte // Accumulated encoded data not yet output
	boxSize int    // Maximum size of each output chunk (box)
}

// NewCopyStreamEncoder creates a new streaming copy stream encoder.
//
// Parameters:
//   - boxSize: Maximum size of each output chunk (typically MaxPlaintextPayloadLength)
func NewCopyStreamEncoder(boxSize int) *CopyStreamEncoder {
	return &CopyStreamEncoder{
		buffer:  make([]byte, 0),
		boxSize: boxSize,
	}
}

// AddEnvelope adds a CourierEnvelope to the encoder.
// Returns box-sized chunks that are ready to be written to the copy stream channel.
// Any remaining data that doesn't fill a complete box is buffered for the next call.
//
// Example:
//
//	encoder := NewCopyStreamEncoder(1024)
//	chunks, err := encoder.AddEnvelope(envelope1)
//	// Write chunks to copy stream
//	chunks, err = encoder.AddEnvelope(envelope2)
//	// Write more chunks
//	finalChunks := encoder.Flush()
//	// Write final chunks
func (e *CopyStreamEncoder) AddEnvelope(envelope *CourierEnvelope) ([][]byte, error) {
	if envelope == nil {
		return nil, fmt.Errorf("envelope is nil")
	}

	// Serialize the CourierEnvelope using trunnel
	envelopeBytes, err := envelope.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal envelope: %w", err)
	}

	// Write 4-byte length prefix (big-endian)
	lengthPrefix := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthPrefix, uint32(len(envelopeBytes)))

	// Append to buffer
	e.buffer = append(e.buffer, lengthPrefix...)
	e.buffer = append(e.buffer, envelopeBytes...)

	// Extract complete boxes
	return e.extractChunks(), nil
}

// extractChunks extracts complete box-sized chunks from the buffer.
// Leaves any remaining partial data in the buffer.
func (e *CopyStreamEncoder) extractChunks() [][]byte {
	var chunks [][]byte

	for len(e.buffer) >= e.boxSize {
		chunk := make([]byte, e.boxSize)
		copy(chunk, e.buffer[:e.boxSize])
		chunks = append(chunks, chunk)
		e.buffer = e.buffer[e.boxSize:]
	}

	return chunks
}

// Flush returns any remaining buffered data as a final chunk.
// This should be called after adding all envelopes to get the last partial chunk.
// Returns nil if there's no remaining data.
func (e *CopyStreamEncoder) Flush() []byte {
	if len(e.buffer) == 0 {
		return nil
	}

	finalChunk := make([]byte, len(e.buffer))
	copy(finalChunk, e.buffer)
	e.buffer = e.buffer[:0] // Clear buffer

	return finalChunk
}

// Buffered returns the number of bytes currently buffered (not yet output).
func (e *CopyStreamEncoder) Buffered() int {
	return len(e.buffer)
}
