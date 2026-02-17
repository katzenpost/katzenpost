// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonhole

import (
	"encoding/binary"
	"fmt"

	"github.com/katzenpost/katzenpost/pigeonhole/geo"
)

// CopyStreamElement flag constants
const (
	// CopyStreamFlagStart indicates this element is the first in the stream
	CopyStreamFlagStart = 0x01
	// CopyStreamFlagFinal indicates this element is the last in the stream
	CopyStreamFlagFinal = 0x02
)

// CopyStreamElementOverhead is the trunnel overhead: 1 (flags) + 4 (envelope_len)
const CopyStreamElementOverhead = 5

// ===========================================================================
// CLIENT SECTION - Used by client2/pigeonhole.go
// ===========================================================================

// CopyStreamEncoder is a streaming encoder for the copy stream format.
// It accepts CourierEnvelopes incrementally and outputs serialized CopyStreamElements
// ready to be written to BACAP boxes. Each element is sized to fit in one box.
//
// The encoder handles:
// - Serializing envelopes with 4-byte length prefix
// - Chunking into pieces that fit in boxes (accounting for element overhead)
// - Wrapping chunks in CopyStreamElement with proper flags
// - Setting IsStart on first element, IsFinal on last element from Flush()
type CopyStreamEncoder struct {
	buffer       []byte // Accumulated serialized envelope data not yet output
	maxChunkSize int    // Maximum chunk payload size (boxSize - CopyStreamElementOverhead)
	isFirstChunk bool   // Track if we've output any chunks yet
}

// NewCopyStreamEncoder creates a new streaming copy stream encoder.
//
// Parameters:
//   - geometry: Pigeonhole geometry object containing MaxPlaintextPayloadLength
//
// The encoder will create CopyStreamElements with chunk payloads sized to fit
// exactly in a box after accounting for the 5-byte element overhead.
func NewCopyStreamEncoder(geometry *geo.Geometry) *CopyStreamEncoder {
	return &CopyStreamEncoder{
		buffer:       make([]byte, 0),
		maxChunkSize: geometry.MaxPlaintextPayloadLength - CopyStreamElementOverhead,
		isFirstChunk: true,
	}
}

// AddEnvelope adds a CourierEnvelope to the encoder.
// Returns serialized CopyStreamElements ready to be written to boxes.
// Any remaining data that doesn't fill a complete element is buffered for the next call.
//
// The first element produced will have the IsStart flag set.
// Note: AddEnvelope always leaves at least one chunk's worth of data in the buffer
// to ensure Flush() can set the IsFinal flag on the last element.
//
// Example:
//
//	encoder := NewCopyStreamEncoder(geometry)
//	elements, err := encoder.AddEnvelope(envelope1)
//	// Write elements to boxes
//	elements, err = encoder.AddEnvelope(envelope2)
//	// Write more elements
//	finalElements := encoder.Flush()
//	// Write final elements (last one has IsFinal flag)
func (e *CopyStreamEncoder) AddEnvelope(envelope *CourierEnvelope) ([][]byte, error) {
	if envelope == nil {
		return nil, fmt.Errorf("envelope is nil")
	}

	// Serialize the CourierEnvelope using trunnel
	envelopeBytes, err := envelope.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal envelope: %w", err)
	}

	// Write 4-byte length prefix (big-endian) + envelope bytes
	lengthPrefix := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthPrefix, uint32(len(envelopeBytes)))
	e.buffer = append(e.buffer, lengthPrefix...)
	e.buffer = append(e.buffer, envelopeBytes...)

	// Extract elements, leaving data for Flush() to emit with IsFinal
	return e.extractElements(), nil
}

// extractElements extracts CopyStreamElements from the buffer.
// Always leaves at least one chunk's worth of data in the buffer so that
// Flush() can emit the final element with the IsFinal flag.
func (e *CopyStreamEncoder) extractElements() [][]byte {
	var elements [][]byte

	for len(e.buffer) > e.maxChunkSize {
		// Extract chunk data
		chunkData := make([]byte, e.maxChunkSize)
		copy(chunkData, e.buffer[:e.maxChunkSize])
		e.buffer = e.buffer[e.maxChunkSize:]

		// Build flags
		var flags uint8
		if e.isFirstChunk {
			flags |= CopyStreamFlagStart
			e.isFirstChunk = false
		}
		// Note: IsFinal is only set in Flush(), not here

		// Create element
		elem := &CopyStreamElement{
			Flags:        flags,
			EnvelopeLen:  uint32(len(chunkData)),
			EnvelopeData: chunkData,
		}

		elemBytes, err := elem.MarshalBinary()
		if err != nil {
			// Should not happen with valid data
			continue
		}
		elements = append(elements, elemBytes)
	}

	return elements
}

// Flush returns all remaining buffered data as CopyStreamElement(s).
// The last element will have the IsFinal flag set.
// This should be called after adding all envelopes.
// Returns nil if there's no remaining data.
func (e *CopyStreamEncoder) Flush() [][]byte {
	if len(e.buffer) == 0 {
		return nil
	}

	var elements [][]byte

	// Extract any complete chunks first (all but the last)
	for len(e.buffer) > e.maxChunkSize {
		chunkData := make([]byte, e.maxChunkSize)
		copy(chunkData, e.buffer[:e.maxChunkSize])
		e.buffer = e.buffer[e.maxChunkSize:]

		var flags uint8
		if e.isFirstChunk {
			flags |= CopyStreamFlagStart
			e.isFirstChunk = false
		}

		elem := &CopyStreamElement{
			Flags:        flags,
			EnvelopeLen:  uint32(len(chunkData)),
			EnvelopeData: chunkData,
		}

		elemBytes, err := elem.MarshalBinary()
		if err != nil {
			continue
		}
		elements = append(elements, elemBytes)
	}

	// Create the final element with IsFinal flag
	chunkData := make([]byte, len(e.buffer))
	copy(chunkData, e.buffer)
	e.buffer = e.buffer[:0]

	var flags uint8
	if e.isFirstChunk {
		flags |= CopyStreamFlagStart
		e.isFirstChunk = false
	}
	flags |= CopyStreamFlagFinal

	elem := &CopyStreamElement{
		Flags:        flags,
		EnvelopeLen:  uint32(len(chunkData)),
		EnvelopeData: chunkData,
	}

	elemBytes, err := elem.MarshalBinary()
	if err == nil {
		elements = append(elements, elemBytes)
	}

	return elements
}

// ===========================================================================
// COURIER SECTION - Used by courier/server/plugin.go
// ===========================================================================

// CopyStreamDecoder is a streaming decoder for the copy stream format.
// It accumulates data from multiple boxes and emits complete CopyStreamElements
// as they become available.
type CopyStreamDecoder struct {
	buffer         []byte // Accumulated bytes from boxes
	maxElementSize int    // Maximum size of a single element (for sanity checking)
}

// NewCopyStreamDecoder creates a new streaming copy stream decoder.
//
// Parameters:
//   - geometry: The pigeonhole geometry object, used to determine max element size
func NewCopyStreamDecoder(geometry *geo.Geometry) *CopyStreamDecoder {
	return &CopyStreamDecoder{
		buffer:         make([]byte, 0),
		maxElementSize: geometry.MaxPlaintextPayloadLength,
	}
}

// AddData adds data from a box to the decoder's buffer.
// Call this each time you read a new box from the copy stream channel.
func (d *CopyStreamDecoder) AddData(data []byte) {
	d.buffer = append(d.buffer, data...)
}

// DecodeAvailable attempts to decode one complete CopyStreamElement from the current buffer.
// Returns a pointer to the decoded element (nil if no complete element available) and any error encountered.
// Incomplete elements remain in the buffer for the next call.
//
// This should be called after each AddData() to extract any complete element.
// Given the geometry (CourierEnvelope ~1300 bytes, Box ~1000 bytes), at most one element
// will be available per call.
func (d *CopyStreamDecoder) DecodeAvailable() (*CopyStreamElement, error) {
	// Minimum size is 5 bytes (flags + length, with empty envelope)
	if len(d.buffer) < CopyStreamElementOverhead {
		return nil, nil
	}

	// Security: validate length before parsing to prevent large allocations from
	// malicious length values. This duplicates wire format knowledge but is necessary
	// to avoid DoS via memory exhaustion.
	// Wire format: [1-byte flags][4-byte envelope_len][envelope_data...]
	length := binary.BigEndian.Uint32(d.buffer[1:5])
	totalSize := CopyStreamElementOverhead + int(length)
	if d.maxElementSize > 0 && totalSize > d.maxElementSize {
		return nil, fmt.Errorf("element size %d exceeds maximum (%d)", totalSize, d.maxElementSize)
	}

	// Try to parse using trunnel
	elem := &CopyStreamElement{}
	remaining, err := elem.Parse(d.buffer)
	if err != nil {
		// "data too short" means we need more data, not an error
		if err.Error() == "data too short" {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to parse element: %w", err)
	}

	// Remove processed element from buffer
	d.buffer = remaining

	return elem, nil
}

// Remaining returns the number of bytes remaining in the decoder's buffer.
func (d *CopyStreamDecoder) Remaining() int {
	return len(d.buffer)
}

// IsStart returns true if this element has the start flag set.
func (elem *CopyStreamElement) IsStart() bool {
	return elem.Flags&CopyStreamFlagStart != 0
}

// IsFinal returns true if this element has the final flag set.
func (elem *CopyStreamElement) IsFinal() bool {
	return elem.Flags&CopyStreamFlagFinal != 0
}

// CopyStreamEnvelopeDecoder is a higher-level decoder that reconstructs
// CourierEnvelopes from CopyStreamElements. It handles the two-level decoding:
// 1. Parse CopyStreamElement from box data
// 2. Accumulate chunk data and parse complete CourierEnvelopes
//
// This is the decoder the courier uses to process the copy stream.
type CopyStreamEnvelopeDecoder struct {
	elementDecoder *CopyStreamDecoder
	envelopeBuffer []byte // Accumulated envelope stream data
	sawFinal       bool   // Have we seen the final element?
}

// NewCopyStreamEnvelopeDecoder creates a new envelope decoder.
//
// Parameters:
//   - geometry: The pigeonhole geometry object, used to determine max element size
func NewCopyStreamEnvelopeDecoder(geometry *geo.Geometry) *CopyStreamEnvelopeDecoder {
	return &CopyStreamEnvelopeDecoder{
		elementDecoder: NewCopyStreamDecoder(geometry),
		envelopeBuffer: make([]byte, 0),
		sawFinal:       false,
	}
}

// AddBoxData adds raw box data to the decoder.
// Call this each time you read a new box from the copy stream channel.
func (d *CopyStreamEnvelopeDecoder) AddBoxData(data []byte) {
	d.elementDecoder.AddData(data)
}

// DecodeEnvelopes attempts to decode all available CourierEnvelopes from the buffer.
// Returns decoded envelopes, whether the final element has been seen, and any error.
//
// The flow is:
// 1. Parse CopyStreamElements from the element decoder
// 2. Extract chunk data from each element
// 3. Accumulate chunks in envelope buffer
// 4. Parse complete envelopes (4-byte length prefix + envelope bytes)
//
// Returns:
//   - []*CourierEnvelope: Any complete envelopes decoded
//   - bool: True if the final element (IsFinal flag) was encountered
//   - error: Any error encountered
func (d *CopyStreamEnvelopeDecoder) DecodeEnvelopes() ([]*CourierEnvelope, bool, error) {
	// First, extract all available elements and accumulate their chunk data
	for {
		elem, err := d.elementDecoder.DecodeAvailable()
		if err != nil {
			return nil, d.sawFinal, fmt.Errorf("failed to decode element: %w", err)
		}
		if elem == nil {
			break // No more complete elements
		}

		// Extract chunk data from element (EnvelopeData contains the chunk)
		d.envelopeBuffer = append(d.envelopeBuffer, elem.EnvelopeData...)

		if elem.IsFinal() {
			d.sawFinal = true
		}
	}

	// Now parse any complete envelopes from the accumulated buffer
	// Format: [4-byte length][envelope bytes][4-byte length][envelope bytes]...
	var envelopes []*CourierEnvelope

	for {
		// Need at least 4 bytes for length
		if len(d.envelopeBuffer) < 4 {
			break
		}

		// Read envelope length (big-endian)
		envelopeLen := binary.BigEndian.Uint32(d.envelopeBuffer[:4])

		// Check if we have the complete envelope
		totalSize := 4 + int(envelopeLen)
		if len(d.envelopeBuffer) < totalSize {
			break // Need more data
		}

		// Parse the envelope
		envelopeBytes := d.envelopeBuffer[4:totalSize]
		envelope := &CourierEnvelope{}
		remaining, err := envelope.Parse(envelopeBytes)
		if err != nil {
			return envelopes, d.sawFinal, fmt.Errorf("failed to parse envelope: %w", err)
		}
		if len(remaining) > 0 {
			return envelopes, d.sawFinal, fmt.Errorf("envelope has %d trailing bytes", len(remaining))
		}

		envelopes = append(envelopes, envelope)

		// Remove parsed envelope from buffer
		d.envelopeBuffer = d.envelopeBuffer[totalSize:]
	}

	return envelopes, d.sawFinal, nil
}

// Remaining returns the number of bytes remaining in the decoder's buffers.
// This includes both unparsed element data and unparsed envelope data.
func (d *CopyStreamEnvelopeDecoder) Remaining() int {
	return d.elementDecoder.Remaining() + len(d.envelopeBuffer)
}
