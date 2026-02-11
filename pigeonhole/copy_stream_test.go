// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonhole

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// Helper function to create a test CourierEnvelope
func createTestCourierEnvelope(ciphertextSize int) *CourierEnvelope {
	senderPubkey := make([]byte, 32)
	rand.Read(senderPubkey)

	ciphertext := make([]byte, ciphertextSize)
	rand.Read(ciphertext)

	var dek1, dek2 [60]byte
	rand.Read(dek1[:])
	rand.Read(dek2[:])

	return &CourierEnvelope{
		IntermediateReplicas: [2]uint8{1, 2},
		Dek1:                 dek1,
		Dek2:                 dek2,
		ReplyIndex:           42,
		Epoch:                12345678901234567890,
		SenderPubkeyLen:      uint16(len(senderPubkey)),
		SenderPubkey:         senderPubkey,
		CiphertextLen:        uint32(len(ciphertext)),
		Ciphertext:           ciphertext,
	}
}

func TestEncodeCopyStream_Empty(t *testing.T) {
	stream, err := EncodeCopyStream([]*CourierEnvelope{})
	require.NoError(t, err)
	require.Empty(t, stream)
}

func TestEncodeCopyStream_SingleEnvelope(t *testing.T) {
	envelope := createTestCourierEnvelope(100)

	stream, err := EncodeCopyStream([]*CourierEnvelope{envelope})
	require.NoError(t, err)
	require.NotEmpty(t, stream)

	// Verify format: [4-byte length][envelope bytes]
	require.GreaterOrEqual(t, len(stream), 4, "Stream should have at least 4 bytes for length prefix")

	// Decode and verify
	decoded, err := DecodeCopyStream(stream)
	require.NoError(t, err)
	require.Len(t, decoded, 1)

	// Verify the decoded envelope matches
	require.Equal(t, envelope.IntermediateReplicas, decoded[0].IntermediateReplicas)
	require.Equal(t, envelope.Dek1, decoded[0].Dek1)
	require.Equal(t, envelope.Dek2, decoded[0].Dek2)
	require.Equal(t, envelope.ReplyIndex, decoded[0].ReplyIndex)
	require.Equal(t, envelope.Epoch, decoded[0].Epoch)
	require.Equal(t, envelope.SenderPubkeyLen, decoded[0].SenderPubkeyLen)
	require.Equal(t, envelope.SenderPubkey, decoded[0].SenderPubkey)
	require.Equal(t, envelope.CiphertextLen, decoded[0].CiphertextLen)
	require.Equal(t, envelope.Ciphertext, decoded[0].Ciphertext)
}

func TestEncodeCopyStream_MultipleEnvelopes(t *testing.T) {
	envelopes := []*CourierEnvelope{
		createTestCourierEnvelope(100),
		createTestCourierEnvelope(200),
		createTestCourierEnvelope(150),
	}

	stream, err := EncodeCopyStream(envelopes)
	require.NoError(t, err)
	require.NotEmpty(t, stream)

	// Decode and verify
	decoded, err := DecodeCopyStream(stream)
	require.NoError(t, err)
	require.Len(t, decoded, 3)

	// Verify each envelope
	for i := 0; i < 3; i++ {
		require.Equal(t, envelopes[i].IntermediateReplicas, decoded[i].IntermediateReplicas)
		require.Equal(t, envelopes[i].CiphertextLen, decoded[i].CiphertextLen)
		require.Equal(t, envelopes[i].Ciphertext, decoded[i].Ciphertext)
	}
}

func TestEncodeCopyStream_LargeEnvelope(t *testing.T) {
	// Create a large envelope (2KB ciphertext)
	envelope := createTestCourierEnvelope(2048)

	stream, err := EncodeCopyStream([]*CourierEnvelope{envelope})
	require.NoError(t, err)

	// Decode and verify
	decoded, err := DecodeCopyStream(stream)
	require.NoError(t, err)
	require.Len(t, decoded, 1)
	require.Equal(t, envelope.Ciphertext, decoded[0].Ciphertext)
}

func TestEncodeCopyStream_NilEnvelope(t *testing.T) {
	envelopes := []*CourierEnvelope{
		createTestCourierEnvelope(100),
		nil, // Nil envelope should cause error
		createTestCourierEnvelope(100),
	}

	_, err := EncodeCopyStream(envelopes)
	require.Error(t, err)
	require.Contains(t, err.Error(), "envelope at index 1 is nil")
}

func TestDecodeCopyStream_Empty(t *testing.T) {
	decoded, err := DecodeCopyStream([]byte{})
	require.NoError(t, err)
	require.Empty(t, decoded)
}

func TestDecodeCopyStream_IncompleteLength(t *testing.T) {
	// Only 3 bytes instead of 4 for length prefix
	data := []byte{0x00, 0x01, 0x02}

	_, err := DecodeCopyStream(data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "incomplete length prefix")
}

func TestDecodeCopyStream_IncompleteEnvelope(t *testing.T) {
	// Length says 100 bytes, but only provide 50
	data := make([]byte, 4+50)
	data[0] = 0x00
	data[1] = 0x00
	data[2] = 0x00
	data[3] = 0x64 // Length = 100

	_, err := DecodeCopyStream(data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "incomplete envelope")
}

func TestDecodeCopyStream_ZeroLength(t *testing.T) {
	// Zero-length envelope should be rejected
	data := []byte{0x00, 0x00, 0x00, 0x00}

	_, err := DecodeCopyStream(data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid zero-length envelope")
}

func TestDecodeCopyStream_ExcessiveLength(t *testing.T) {
	// Length exceeds 1MB sanity check
	data := make([]byte, 4)
	data[0] = 0x01 // 16MB
	data[1] = 0x00
	data[2] = 0x00
	data[3] = 0x00

	_, err := DecodeCopyStream(data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds maximum")
}

func TestDecodeCopyStream_InvalidTrunnelData(t *testing.T) {
	// Valid length prefix but invalid trunnel data
	data := make([]byte, 4+10)
	data[0] = 0x00
	data[1] = 0x00
	data[2] = 0x00
	data[3] = 0x0A // Length = 10
	// Fill with garbage
	for i := 4; i < len(data); i++ {
		data[i] = 0xFF
	}

	_, err := DecodeCopyStream(data)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse envelope")
}

func TestEncodeDecode_RoundTrip(t *testing.T) {
	// Test round-trip encoding and decoding with various envelope sizes
	testCases := []struct {
		name           string
		envelopeCount  int
		ciphertextSize int
	}{
		{"Single small envelope", 1, 50},
		{"Single medium envelope", 1, 500},
		{"Single large envelope", 1, 2000},
		{"Multiple small envelopes", 5, 100},
		{"Multiple medium envelopes", 3, 800},
		{"Multiple large envelopes", 2, 1500},
		{"Many tiny envelopes", 10, 10},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test envelopes
			envelopes := make([]*CourierEnvelope, tc.envelopeCount)
			for i := 0; i < tc.envelopeCount; i++ {
				envelopes[i] = createTestCourierEnvelope(tc.ciphertextSize)
			}

			// Encode
			stream, err := EncodeCopyStream(envelopes)
			require.NoError(t, err)
			require.NotEmpty(t, stream)

			// Decode
			decoded, err := DecodeCopyStream(stream)
			require.NoError(t, err)
			require.Len(t, decoded, tc.envelopeCount)

			// Verify each envelope matches
			for i := 0; i < tc.envelopeCount; i++ {
				require.Equal(t, envelopes[i].IntermediateReplicas, decoded[i].IntermediateReplicas)
				require.Equal(t, envelopes[i].Dek1, decoded[i].Dek1)
				require.Equal(t, envelopes[i].Dek2, decoded[i].Dek2)
				require.Equal(t, envelopes[i].ReplyIndex, decoded[i].ReplyIndex)
				require.Equal(t, envelopes[i].Epoch, decoded[i].Epoch)
				require.Equal(t, envelopes[i].SenderPubkeyLen, decoded[i].SenderPubkeyLen)
				require.Equal(t, envelopes[i].SenderPubkey, decoded[i].SenderPubkey)
				require.Equal(t, envelopes[i].CiphertextLen, decoded[i].CiphertextLen)
				require.Equal(t, envelopes[i].Ciphertext, decoded[i].Ciphertext)
			}
		})
	}
}

func TestEncodeDecode_StreamFormat(t *testing.T) {
	// Test that the stream format is correct: [len1][env1][len2][env2]...
	envelope1 := createTestCourierEnvelope(100)
	envelope2 := createTestCourierEnvelope(200)

	stream, err := EncodeCopyStream([]*CourierEnvelope{envelope1, envelope2})
	require.NoError(t, err)

	// Manually verify the format
	offset := 0

	// First envelope
	length1 := int(stream[0])<<24 | int(stream[1])<<16 | int(stream[2])<<8 | int(stream[3])
	offset += 4
	require.Greater(t, length1, 0)
	require.Less(t, length1, len(stream))
	offset += length1

	// Second envelope
	require.Less(t, offset+4, len(stream), "Should have second length prefix")
	length2 := int(stream[offset])<<24 | int(stream[offset+1])<<16 | int(stream[offset+2])<<8 | int(stream[offset+3])
	offset += 4
	require.Greater(t, length2, 0)
	offset += length2

	// Should have consumed entire stream
	require.Equal(t, len(stream), offset)
}

func TestDecodeCopyStream_PartialRead(t *testing.T) {
	// Test decoding when we have complete envelopes followed by incomplete data
	envelopes := []*CourierEnvelope{
		createTestCourierEnvelope(100),
		createTestCourierEnvelope(150),
	}

	stream, err := EncodeCopyStream(envelopes)
	require.NoError(t, err)

	// Decode full stream - should work
	decoded, err := DecodeCopyStream(stream)
	require.NoError(t, err)
	require.Len(t, decoded, 2)

	// Decode partial stream (cut off in the middle of second envelope) - should fail
	partialStream := stream[:len(stream)-50]
	_, err = DecodeCopyStream(partialStream)
	require.Error(t, err)
}

func TestEncodeCopyStream_DeterministicEncoding(t *testing.T) {
	// Test that encoding the same envelope twice produces identical output
	envelope := createTestCourierEnvelope(100)

	stream1, err := EncodeCopyStream([]*CourierEnvelope{envelope})
	require.NoError(t, err)

	stream2, err := EncodeCopyStream([]*CourierEnvelope{envelope})
	require.NoError(t, err)

	require.True(t, bytes.Equal(stream1, stream2), "Encoding should be deterministic")
}

func TestCopyStreamDecoder_SingleBox(t *testing.T) {
	// Create envelopes and encode them
	envelopes := []*CourierEnvelope{
		createTestCourierEnvelope(100),
		createTestCourierEnvelope(150),
	}

	stream, err := EncodeCopyStream(envelopes)
	require.NoError(t, err)

	// Decode using streaming decoder with all data in one box
	decoder := NewCopyStreamDecoder()
	decoder.AddData(stream)

	decoded, err := decoder.DecodeAvailable()
	require.NoError(t, err)
	require.Len(t, decoded, 2)
	require.Equal(t, 0, decoder.Remaining())

	// Verify envelopes match
	for i := 0; i < 2; i++ {
		require.Equal(t, envelopes[i].Ciphertext, decoded[i].Ciphertext)
	}
}

func TestCopyStreamDecoder_MultipleBoxes(t *testing.T) {
	// Create envelopes and encode them
	envelopes := []*CourierEnvelope{
		createTestCourierEnvelope(500),
		createTestCourierEnvelope(600),
		createTestCourierEnvelope(700),
	}

	stream, err := EncodeCopyStream(envelopes)
	require.NoError(t, err)

	// Split stream into box-sized chunks (simulate BACAP boxes)
	boxSize := 400
	decoder := NewCopyStreamDecoder()
	var allDecoded []*CourierEnvelope

	for offset := 0; offset < len(stream); offset += boxSize {
		end := offset + boxSize
		if end > len(stream) {
			end = len(stream)
		}
		chunk := stream[offset:end]

		// Add box data
		decoder.AddData(chunk)

		// Decode available envelopes
		decoded, err := decoder.DecodeAvailable()
		require.NoError(t, err)
		allDecoded = append(allDecoded, decoded...)
	}

	// Verify all envelopes were decoded
	require.Len(t, allDecoded, 3)
	require.Equal(t, 0, decoder.Remaining())

	for i := 0; i < 3; i++ {
		require.Equal(t, envelopes[i].Ciphertext, allDecoded[i].Ciphertext)
	}
}

func TestCopyStreamDecoder_PartialEnvelope(t *testing.T) {
	// Create envelope and encode it
	envelope := createTestCourierEnvelope(1000)
	stream, err := EncodeCopyStream([]*CourierEnvelope{envelope})
	require.NoError(t, err)

	// Split in the middle of the envelope
	decoder := NewCopyStreamDecoder()

	// Add first half
	decoder.AddData(stream[:len(stream)/2])
	decoded, err := decoder.DecodeAvailable()
	require.NoError(t, err)
	require.Len(t, decoded, 0, "Should not decode incomplete envelope")
	require.Greater(t, decoder.Remaining(), 0, "Should have data in buffer")

	// Add second half
	decoder.AddData(stream[len(stream)/2:])
	decoded, err = decoder.DecodeAvailable()
	require.NoError(t, err)
	require.Len(t, decoded, 1, "Should decode complete envelope")
	require.Equal(t, 0, decoder.Remaining())
	require.Equal(t, envelope.Ciphertext, decoded[0].Ciphertext)
}

func TestCopyStreamDecoder_InvalidLength(t *testing.T) {
	decoder := NewCopyStreamDecoder()

	// Add data with zero length
	data := []byte{0x00, 0x00, 0x00, 0x00}
	decoder.AddData(data)

	_, err := decoder.DecodeAvailable()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid zero-length envelope")
}

func TestCopyStreamDecoder_ExcessiveLength(t *testing.T) {
	decoder := NewCopyStreamDecoder()

	// Add data with excessive length (16MB)
	data := []byte{0x01, 0x00, 0x00, 0x00}
	decoder.AddData(data)

	_, err := decoder.DecodeAvailable()
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds maximum")
}

func TestCopyStreamDecoder_IncrementalDecoding(t *testing.T) {
	// Create multiple envelopes
	envelopes := []*CourierEnvelope{
		createTestCourierEnvelope(200),
		createTestCourierEnvelope(300),
		createTestCourierEnvelope(250),
	}

	stream, err := EncodeCopyStream(envelopes)
	require.NoError(t, err)

	// Feed data byte-by-byte (extreme case)
	decoder := NewCopyStreamDecoder()
	var allDecoded []*CourierEnvelope

	for i := 0; i < len(stream); i++ {
		decoder.AddData(stream[i : i+1])
		decoded, err := decoder.DecodeAvailable()
		require.NoError(t, err)
		allDecoded = append(allDecoded, decoded...)
	}

	require.Len(t, allDecoded, 3)
	require.Equal(t, 0, decoder.Remaining())
}

func TestCopyStreamEncoder_SingleEnvelope(t *testing.T) {
	envelope := createTestCourierEnvelope(500)
	boxSize := 1024

	encoder := NewCopyStreamEncoder(boxSize)
	chunks, err := encoder.AddEnvelope(envelope)
	require.NoError(t, err)

	// Envelope should fit in buffer, no chunks yet
	require.Empty(t, chunks)
	require.Greater(t, encoder.Buffered(), 0)

	// Flush to get final chunk
	finalChunk := encoder.Flush()
	require.NotNil(t, finalChunk)

	// Decode and verify
	decoded, err := DecodeCopyStream(finalChunk)
	require.NoError(t, err)
	require.Len(t, decoded, 1)
	require.Equal(t, envelope.Ciphertext, decoded[0].Ciphertext)
}

func TestCopyStreamEncoder_MultipleEnvelopes(t *testing.T) {
	envelopes := []*CourierEnvelope{
		createTestCourierEnvelope(400),
		createTestCourierEnvelope(500),
		createTestCourierEnvelope(600),
	}
	boxSize := 1024

	encoder := NewCopyStreamEncoder(boxSize)
	var allChunks [][]byte

	for _, envelope := range envelopes {
		chunks, err := encoder.AddEnvelope(envelope)
		require.NoError(t, err)
		allChunks = append(allChunks, chunks...)
	}

	// Get final chunk
	finalChunk := encoder.Flush()
	if finalChunk != nil {
		allChunks = append(allChunks, finalChunk)
	}

	// Reconstruct stream
	var stream []byte
	for _, chunk := range allChunks {
		stream = append(stream, chunk...)
	}

	// Decode and verify
	decoded, err := DecodeCopyStream(stream)
	require.NoError(t, err)
	require.Len(t, decoded, 3)

	for i := 0; i < 3; i++ {
		require.Equal(t, envelopes[i].Ciphertext, decoded[i].Ciphertext)
	}
}

func TestCopyStreamEncoder_LargeEnvelopes(t *testing.T) {
	// Create envelopes that will span multiple boxes
	envelopes := []*CourierEnvelope{
		createTestCourierEnvelope(2000),
		createTestCourierEnvelope(2500),
	}
	boxSize := 1024

	encoder := NewCopyStreamEncoder(boxSize)
	var allChunks [][]byte

	for _, envelope := range envelopes {
		chunks, err := encoder.AddEnvelope(envelope)
		require.NoError(t, err)
		allChunks = append(allChunks, chunks...)
	}

	finalChunk := encoder.Flush()
	if finalChunk != nil {
		allChunks = append(allChunks, finalChunk)
	}

	// Should have multiple chunks
	require.Greater(t, len(allChunks), 1)

	// Verify all chunks except last are exactly boxSize
	for i := 0; i < len(allChunks)-1; i++ {
		require.Equal(t, boxSize, len(allChunks[i]))
	}

	// Reconstruct and decode
	var stream []byte
	for _, chunk := range allChunks {
		stream = append(stream, chunk...)
	}

	decoded, err := DecodeCopyStream(stream)
	require.NoError(t, err)
	require.Len(t, decoded, 2)

	for i := 0; i < 2; i++ {
		require.Equal(t, envelopes[i].Ciphertext, decoded[i].Ciphertext)
	}
}

func TestCopyStreamEncoder_RoundTripWithDecoder(t *testing.T) {
	// Test encoder -> decoder round trip
	envelopes := []*CourierEnvelope{
		createTestCourierEnvelope(300),
		createTestCourierEnvelope(400),
		createTestCourierEnvelope(500),
	}
	boxSize := 800

	// Encode
	encoder := NewCopyStreamEncoder(boxSize)
	var chunks [][]byte

	for _, envelope := range envelopes {
		newChunks, err := encoder.AddEnvelope(envelope)
		require.NoError(t, err)
		chunks = append(chunks, newChunks...)
	}

	finalChunk := encoder.Flush()
	if finalChunk != nil {
		chunks = append(chunks, finalChunk)
	}

	// Decode using streaming decoder
	decoder := NewCopyStreamDecoder()
	var allDecoded []*CourierEnvelope

	for _, chunk := range chunks {
		decoder.AddData(chunk)
		decoded, err := decoder.DecodeAvailable()
		require.NoError(t, err)
		allDecoded = append(allDecoded, decoded...)
	}

	// Verify
	require.Len(t, allDecoded, 3)
	require.Equal(t, 0, decoder.Remaining())

	for i := 0; i < 3; i++ {
		require.Equal(t, envelopes[i].Ciphertext, allDecoded[i].Ciphertext)
	}
}

func TestCopyStreamEncoder_NilEnvelope(t *testing.T) {
	encoder := NewCopyStreamEncoder(1024)
	_, err := encoder.AddEnvelope(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "envelope is nil")
}

func TestCopyStreamEncoder_EmptyFlush(t *testing.T) {
	encoder := NewCopyStreamEncoder(1024)
	finalChunk := encoder.Flush()
	require.Nil(t, finalChunk)
	require.Equal(t, 0, encoder.Buffered())
}
