// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonhole

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/pigeonhole/geo"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// createTestEnvelope creates a simple test CourierEnvelope with the given ciphertext size.
func createTestEnvelope(ciphertextSize int) *CourierEnvelope {
	return &CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1},
		Dek1:                 [60]uint8{},
		Dek2:                 [60]uint8{},
		ReplyIndex:           0,
		Epoch:                12345,
		SenderPubkeyLen:      32,
		SenderPubkey:         make([]byte, 32),
		CiphertextLen:        uint32(ciphertextSize),
		Ciphertext:           make([]byte, ciphertextSize),
	}
}

// createTestGeometry creates a geometry with the given max plaintext payload length.
// Uses the same NIKE scheme (CTIDH1024-X25519) that the courier and client use.
func createTestGeometry(maxPlaintextPayloadLength int) *geo.Geometry {
	return geo.NewGeometry(maxPlaintextPayloadLength, replicaCommon.NikeScheme)
}

// ===========================================================================
// CLIENT SIDE TESTS - CopyStreamEncoder
// ===========================================================================

func TestCopyStreamEncoder_NewEncoder(t *testing.T) {
	geometry := createTestGeometry(1000)
	encoder := NewCopyStreamEncoder(geometry)

	require.NotNil(t, encoder)
	require.Equal(t, 1000-CopyStreamElementOverhead, encoder.maxChunkSize)
	require.True(t, encoder.isFirstChunk)
	require.Empty(t, encoder.buffer)
}

func TestCopyStreamEncoder_AddEnvelope_NilEnvelope(t *testing.T) {
	geometry := createTestGeometry(1000)
	encoder := NewCopyStreamEncoder(geometry)

	elements, err := encoder.AddEnvelope(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "envelope is nil")
	require.Nil(t, elements)
}

func TestCopyStreamEncoder_SmallEnvelope_BufferedForFlush(t *testing.T) {
	// Small envelope that doesn't fill a complete chunk
	geometry := createTestGeometry(1000)
	encoder := NewCopyStreamEncoder(geometry)

	envelope := createTestEnvelope(100)
	elements, err := encoder.AddEnvelope(envelope)

	require.NoError(t, err)
	// Small envelope should be buffered, not emitted (leaves data for Flush)
	require.Empty(t, elements)
	require.NotEmpty(t, encoder.buffer)
}

func TestCopyStreamEncoder_LargeEnvelope_ProducesElements(t *testing.T) {
	// Large envelope that spans multiple chunks
	geometry := createTestGeometry(200) // Small box size for testing
	encoder := NewCopyStreamEncoder(geometry)

	// Create an envelope larger than maxChunkSize
	envelope := createTestEnvelope(500)
	elements, err := encoder.AddEnvelope(envelope)

	require.NoError(t, err)
	require.NotEmpty(t, elements)

	// First element should have IsStart flag
	firstElem := &CopyStreamElement{}
	_, err = firstElem.Parse(elements[0])
	require.NoError(t, err)
	require.True(t, firstElem.IsStart(), "first element should have IsStart flag")
	require.False(t, firstElem.IsFinal(), "non-flushed elements should not have IsFinal flag")
}

func TestCopyStreamEncoder_Flush_SetsFinalFlag(t *testing.T) {
	geometry := createTestGeometry(1000)
	encoder := NewCopyStreamEncoder(geometry)

	envelope := createTestEnvelope(100)
	_, err := encoder.AddEnvelope(envelope)
	require.NoError(t, err)

	finalElements := encoder.Flush()
	require.NotEmpty(t, finalElements)

	// Last element should have IsFinal flag
	lastElem := &CopyStreamElement{}
	_, err = lastElem.Parse(finalElements[len(finalElements)-1])
	require.NoError(t, err)
	require.True(t, lastElem.IsFinal(), "last element from Flush should have IsFinal flag")
}

func TestCopyStreamEncoder_Flush_SingleEnvelope_HasBothFlags(t *testing.T) {
	// Single small envelope - the final element should have both IsStart and IsFinal
	geometry := createTestGeometry(1000)
	encoder := NewCopyStreamEncoder(geometry)

	envelope := createTestEnvelope(50)
	_, err := encoder.AddEnvelope(envelope)
	require.NoError(t, err)

	finalElements := encoder.Flush()
	require.Len(t, finalElements, 1)

	elem := &CopyStreamElement{}
	_, err = elem.Parse(finalElements[0])
	require.NoError(t, err)
	require.True(t, elem.IsStart(), "single element should have IsStart flag")
	require.True(t, elem.IsFinal(), "single element should have IsFinal flag")
}

func TestCopyStreamEncoder_Flush_EmptyBuffer_ReturnsNil(t *testing.T) {
	geometry := createTestGeometry(1000)
	encoder := NewCopyStreamEncoder(geometry)

	// Flush without adding anything
	elements := encoder.Flush()
	require.Nil(t, elements)
}

func TestCopyStreamEncoder_MultipleEnvelopes(t *testing.T) {
	geometry := createTestGeometry(500)
	encoder := NewCopyStreamEncoder(geometry)

	// Add multiple envelopes
	envelope1 := createTestEnvelope(100)
	envelope2 := createTestEnvelope(150)
	envelope3 := createTestEnvelope(120)

	var allElements [][]byte

	elems, err := encoder.AddEnvelope(envelope1)
	require.NoError(t, err)
	allElements = append(allElements, elems...)

	elems, err = encoder.AddEnvelope(envelope2)
	require.NoError(t, err)
	allElements = append(allElements, elems...)

	elems, err = encoder.AddEnvelope(envelope3)
	require.NoError(t, err)
	allElements = append(allElements, elems...)

	finalElems := encoder.Flush()
	allElements = append(allElements, finalElems...)

	require.NotEmpty(t, allElements)
}

// ===========================================================================
// COURIER SIDE TESTS - CopyStreamDecoder and CopyStreamEnvelopeDecoder
// ===========================================================================

func TestCopyStreamDecoder_NewDecoder(t *testing.T) {
	geometry := createTestGeometry(2000)
	decoder := NewCopyStreamDecoder(geometry)

	require.NotNil(t, decoder)
	require.Equal(t, 2000, decoder.maxElementSize)
	require.Empty(t, decoder.buffer)
}

func TestCopyStreamDecoder_AddData(t *testing.T) {
	geometry := createTestGeometry(2000)
	decoder := NewCopyStreamDecoder(geometry)

	decoder.AddData([]byte{1, 2, 3})
	require.Equal(t, 3, decoder.Remaining())

	decoder.AddData([]byte{4, 5})
	require.Equal(t, 5, decoder.Remaining())
}

func TestCopyStreamDecoder_DecodeAvailable_InsufficientData(t *testing.T) {
	geometry := createTestGeometry(2000)
	decoder := NewCopyStreamDecoder(geometry)

	// Add less than 5 bytes (minimum element size)
	decoder.AddData([]byte{0, 0, 0})

	elem, err := decoder.DecodeAvailable()
	require.NoError(t, err)
	require.Nil(t, elem, "should return nil when insufficient data")
}

func TestCopyStreamDecoder_DecodeAvailable_CompleteElement(t *testing.T) {
	geometry := createTestGeometry(2000)
	decoder := NewCopyStreamDecoder(geometry)

	// Create a valid element and serialize it
	originalElem := &CopyStreamElement{
		Flags:        CopyStreamFlagStart,
		EnvelopeLen:  5,
		EnvelopeData: []byte{1, 2, 3, 4, 5},
	}
	elemBytes, err := originalElem.MarshalBinary()
	require.NoError(t, err)

	decoder.AddData(elemBytes)

	elem, err := decoder.DecodeAvailable()
	require.NoError(t, err)
	require.NotNil(t, elem)
	require.True(t, elem.IsStart())
	require.Equal(t, uint32(5), elem.EnvelopeLen)
	require.Equal(t, []byte{1, 2, 3, 4, 5}, elem.EnvelopeData)
}

func TestCopyStreamDecoder_DecodeAvailable_ElementTooLarge(t *testing.T) {
	geometry := createTestGeometry(10) // Very small max size
	decoder := NewCopyStreamDecoder(geometry)

	// Create an element larger than max
	originalElem := &CopyStreamElement{
		Flags:        0,
		EnvelopeLen:  100,
		EnvelopeData: make([]byte, 100),
	}
	elemBytes, err := originalElem.MarshalBinary()
	require.NoError(t, err)

	decoder.AddData(elemBytes)

	_, err = decoder.DecodeAvailable()
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds maximum")
}

func TestCopyStreamDecoder_Remaining(t *testing.T) {
	geometry := createTestGeometry(2000)
	decoder := NewCopyStreamDecoder(geometry)

	require.Equal(t, 0, decoder.Remaining())

	decoder.AddData([]byte{1, 2, 3, 4, 5})
	require.Equal(t, 5, decoder.Remaining())
}

func TestCopyStreamEnvelopeDecoder_NewDecoder(t *testing.T) {
	geometry := createTestGeometry(2000)
	decoder := NewCopyStreamEnvelopeDecoder(geometry)

	require.NotNil(t, decoder)
	require.NotNil(t, decoder.elementDecoder)
	require.Empty(t, decoder.envelopeBuffer)
	require.False(t, decoder.sawFinal)
}

func TestCopyStreamEnvelopeDecoder_Remaining(t *testing.T) {
	geometry := createTestGeometry(2000)
	decoder := NewCopyStreamEnvelopeDecoder(geometry)

	require.Equal(t, 0, decoder.Remaining())

	decoder.AddBoxData([]byte{1, 2, 3})
	require.Equal(t, 3, decoder.Remaining())
}

// ===========================================================================
// ROUND-TRIP TESTS - Encoder → Decoder Integration
// ===========================================================================

func TestCopyStream_RoundTrip_SingleEnvelope(t *testing.T) {
	geometry := createTestGeometry(1000)

	// Create encoder and add envelope
	encoder := NewCopyStreamEncoder(geometry)
	originalEnvelope := createTestEnvelope(100)

	elements, err := encoder.AddEnvelope(originalEnvelope)
	require.NoError(t, err)
	finalElements := encoder.Flush()
	allElements := append(elements, finalElements...)

	// Create decoder and decode (use same geometry)
	decoder := NewCopyStreamEnvelopeDecoder(geometry)
	for _, elem := range allElements {
		decoder.AddBoxData(elem)
	}

	envelopes, isFinal, err := decoder.DecodeEnvelopes()
	require.NoError(t, err)
	require.True(t, isFinal)
	require.Len(t, envelopes, 1)

	// Verify envelope contents
	decoded := envelopes[0]
	require.Equal(t, originalEnvelope.IntermediateReplicas, decoded.IntermediateReplicas)
	require.Equal(t, originalEnvelope.Epoch, decoded.Epoch)
	require.Equal(t, originalEnvelope.CiphertextLen, decoded.CiphertextLen)
}

func TestCopyStream_RoundTrip_MultipleEnvelopes(t *testing.T) {
	geometry := createTestGeometry(500)

	// Create encoder and add multiple envelopes
	encoder := NewCopyStreamEncoder(geometry)
	originalEnvelopes := []*CourierEnvelope{
		createTestEnvelope(100),
		createTestEnvelope(150),
		createTestEnvelope(80),
	}

	var allElements [][]byte
	for _, env := range originalEnvelopes {
		elements, err := encoder.AddEnvelope(env)
		require.NoError(t, err)
		allElements = append(allElements, elements...)
	}
	finalElements := encoder.Flush()
	allElements = append(allElements, finalElements...)

	// Create decoder and decode (use same geometry)
	decoder := NewCopyStreamEnvelopeDecoder(geometry)
	for _, elem := range allElements {
		decoder.AddBoxData(elem)
	}

	envelopes, isFinal, err := decoder.DecodeEnvelopes()
	require.NoError(t, err)
	require.True(t, isFinal)
	require.Len(t, envelopes, 3)

	// Verify each envelope
	for i, decoded := range envelopes {
		require.Equal(t, originalEnvelopes[i].CiphertextLen, decoded.CiphertextLen)
		require.Equal(t, originalEnvelopes[i].Epoch, decoded.Epoch)
	}
}

func TestCopyStream_RoundTrip_LargeEnvelope(t *testing.T) {
	// Test envelope larger than a single box
	geometry := createTestGeometry(200)

	encoder := NewCopyStreamEncoder(geometry)
	originalEnvelope := createTestEnvelope(500) // Larger than box

	elements, err := encoder.AddEnvelope(originalEnvelope)
	require.NoError(t, err)
	finalElements := encoder.Flush()
	allElements := append(elements, finalElements...)

	// Should produce multiple elements
	require.Greater(t, len(allElements), 1, "large envelope should produce multiple elements")

	// Decode (use same geometry)
	decoder := NewCopyStreamEnvelopeDecoder(geometry)
	for _, elem := range allElements {
		decoder.AddBoxData(elem)
	}

	envelopes, isFinal, err := decoder.DecodeEnvelopes()
	require.NoError(t, err)
	require.True(t, isFinal)
	require.Len(t, envelopes, 1)
	require.Equal(t, originalEnvelope.CiphertextLen, envelopes[0].CiphertextLen)
}

func TestCopyStream_RoundTrip_IncrementalDecoding(t *testing.T) {
	// Simulate courier reading boxes one at a time
	geometry := createTestGeometry(200)

	encoder := NewCopyStreamEncoder(geometry)
	envelope := createTestEnvelope(300)

	elements, err := encoder.AddEnvelope(envelope)
	require.NoError(t, err)
	finalElements := encoder.Flush()
	allElements := append(elements, finalElements...)

	decoder := NewCopyStreamEnvelopeDecoder(geometry)
	var decodedEnvelopes []*CourierEnvelope
	sawFinal := false

	// Feed elements one at a time
	for _, elem := range allElements {
		decoder.AddBoxData(elem)
		envs, isFinal, err := decoder.DecodeEnvelopes()
		require.NoError(t, err)
		decodedEnvelopes = append(decodedEnvelopes, envs...)
		if isFinal {
			sawFinal = true
		}
	}

	require.True(t, sawFinal)
	require.Len(t, decodedEnvelopes, 1)
}

func TestCopyStreamElement_Flags(t *testing.T) {
	t.Run("IsStart", func(t *testing.T) {
		elem := &CopyStreamElement{Flags: CopyStreamFlagStart}
		require.True(t, elem.IsStart())
		require.False(t, elem.IsFinal())
	})

	t.Run("IsFinal", func(t *testing.T) {
		elem := &CopyStreamElement{Flags: CopyStreamFlagFinal}
		require.False(t, elem.IsStart())
		require.True(t, elem.IsFinal())
	})

	t.Run("BothFlags", func(t *testing.T) {
		elem := &CopyStreamElement{Flags: CopyStreamFlagStart | CopyStreamFlagFinal}
		require.True(t, elem.IsStart())
		require.True(t, elem.IsFinal())
	})

	t.Run("NoFlags", func(t *testing.T) {
		elem := &CopyStreamElement{Flags: 0}
		require.False(t, elem.IsStart())
		require.False(t, elem.IsFinal())
	})
}
