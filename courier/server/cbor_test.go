package server

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/replica/common"
)

const (
	// Test message constants to avoid duplication
	testMessage1     = "message 1"
	testMessage2     = "message 2"
	testMessage3     = "message 3"
	testMessage1Long = "test message 1"
	testMessage2Long = "test message 2"

	// Log message constants
	logProcessedEnvelope = "Processed envelope with epoch %d"
	logEnvelopeSize      = "Envelope %d size: %d bytes"
	logBufferLength      = "Buffer length: %d"

	// Test constants
	nikeSchemeX25519  = "x25519"
	envelopeProcessed = "envelope_processed"
)

// Helper functions for common test patterns

// setupNikeScheme initializes and validates the NIKE scheme
func setupNikeScheme(t *testing.T) nike.Scheme {
	nikeScheme := schemes.ByName(nikeSchemeX25519)
	require.NotNil(t, nikeScheme)
	return nikeScheme
}

// createBasicEnvelopeHandler creates a standard envelope handler that logs processed envelopes
func createBasicEnvelopeHandler(t *testing.T, processedEnvelopes *[]*common.CourierEnvelope) func(*common.CourierEnvelope) {
	return func(envelope *common.CourierEnvelope) {
		*processedEnvelopes = append(*processedEnvelopes, envelope)
		t.Logf(logProcessedEnvelope, envelope.Epoch)
	}
}

// createProgressTrackingHandler creates an envelope handler that tracks progress calls
func createProgressTrackingHandler(t *testing.T, processedEnvelopes *[]*common.CourierEnvelope, progressCalls *[]string) func(*common.CourierEnvelope) {
	return func(envelope *common.CourierEnvelope) {
		*processedEnvelopes = append(*processedEnvelopes, envelope)
		*progressCalls = append(*progressCalls, envelopeProcessed)
		t.Logf(logProcessedEnvelope, envelope.Epoch)
	}
}

// createSilentEnvelopeHandler creates an envelope handler that doesn't log
func createSilentEnvelopeHandler(processedEnvelopes *[]*common.CourierEnvelope) func(*common.CourierEnvelope) {
	return func(envelope *common.CourierEnvelope) {
		*processedEnvelopes = append(*processedEnvelopes, envelope)
	}
}

// TestCBORBasicDecoding tests basic CBOR encoding/decoding of CourierEnvelopes
func TestCBORBasicDecoding(t *testing.T) {
	nikeScheme := setupNikeScheme(t)

	// Create a simple test envelope
	envelope := createTestEnvelope(t, []byte("test message"), nikeScheme)

	// Encode to CBOR
	cborData := envelope.Bytes()
	t.Logf("Original envelope CBOR size: %d bytes", len(cborData))

	// Decode back from CBOR
	decodedEnvelope, err := common.CourierEnvelopeFromBytes(cborData)
	require.NoError(t, err)
	require.NotNil(t, decodedEnvelope)

	// Verify fields match
	require.Equal(t, envelope.Epoch, decodedEnvelope.Epoch)
	require.Equal(t, envelope.IsRead, decodedEnvelope.IsRead)
	require.Equal(t, envelope.IntermediateReplicas, decodedEnvelope.IntermediateReplicas)

	t.Log("Basic CBOR encoding/decoding works correctly")
}

// TestCBORConcatenatedDecoding tests decoding multiple concatenated CBOR objects
func TestCBORConcatenatedDecoding(t *testing.T) {
	nikeScheme := setupNikeScheme(t)

	// Create multiple test envelopes
	envelope1 := createTestEnvelope(t, []byte(testMessage1), nikeScheme)
	envelope2 := createTestEnvelope(t, []byte(testMessage2), nikeScheme)
	envelope3 := createTestEnvelope(t, []byte(testMessage3), nikeScheme)

	// Encode each to CBOR
	cbor1 := envelope1.Bytes()
	cbor2 := envelope2.Bytes()
	cbor3 := envelope3.Bytes()

	t.Logf("Envelope sizes: %d, %d, %d bytes", len(cbor1), len(cbor2), len(cbor3))

	// Concatenate all CBOR data
	concatenated := append(cbor1, cbor2...)
	concatenated = append(concatenated, cbor3...)

	t.Logf("Total concatenated size: %d bytes", len(concatenated))

	// Try to decode each envelope from the concatenated data
	offset := 0

	// Decode first envelope
	decoded1, err := common.CourierEnvelopeFromBytes(concatenated[offset : offset+len(cbor1)])
	require.NoError(t, err)
	require.Equal(t, envelope1.Epoch, decoded1.Epoch)
	offset += len(cbor1)

	// Decode second envelope
	decoded2, err := common.CourierEnvelopeFromBytes(concatenated[offset : offset+len(cbor2)])
	require.NoError(t, err)
	require.Equal(t, envelope2.Epoch, decoded2.Epoch)
	offset += len(cbor2)

	// Decode third envelope
	decoded3, err := common.CourierEnvelopeFromBytes(concatenated[offset : offset+len(cbor3)])
	require.NoError(t, err)
	require.Equal(t, envelope3.Epoch, decoded3.Epoch)

	t.Log("Concatenated CBOR decoding works when boundaries are known")
}

// TestStreamingDecoderBasic tests the streaming decoder with complete envelopes
func TestStreamingDecoderBasic(t *testing.T) {
	nikeScheme := setupNikeScheme(t)

	var processedEnvelopes []*common.CourierEnvelope
	handleEnvelope := createBasicEnvelopeHandler(t, &processedEnvelopes)
	decoder := NewStreamingCBORDecoder(handleEnvelope)

	// Create and process single envelope
	envelope1 := createTestEnvelope(t, []byte(testMessage1Long), nikeScheme)
	cbor1 := envelope1.Bytes()

	err := decoder.ProcessChunk(cbor1)
	require.NoError(t, err)
	require.Len(t, processedEnvelopes, 1)
	require.Equal(t, envelope1.Epoch, processedEnvelopes[0].Epoch)

	// Process second envelope
	envelope2 := createTestEnvelope(t, []byte(testMessage2Long), nikeScheme)
	cbor2 := envelope2.Bytes()

	err = decoder.ProcessChunk(cbor2)
	require.NoError(t, err)
	require.Len(t, processedEnvelopes, 2)
	require.Equal(t, envelope2.Epoch, processedEnvelopes[1].Epoch)

	t.Log("Streaming decoder works with complete envelopes")
}

// TestStreamingDecoderConcatenated tests the streaming decoder with concatenated data
func TestStreamingDecoderConcatenated(t *testing.T) {
	nikeScheme := setupNikeScheme(t)

	var processedEnvelopes []*common.CourierEnvelope
	handleEnvelope := createBasicEnvelopeHandler(t, &processedEnvelopes)
	decoder := NewStreamingCBORDecoder(handleEnvelope)

	// Create multiple envelopes
	envelope1 := createTestEnvelope(t, []byte(testMessage1), nikeScheme)
	envelope2 := createTestEnvelope(t, []byte(testMessage2), nikeScheme)
	envelope3 := createTestEnvelope(t, []byte(testMessage3), nikeScheme)

	// Concatenate all CBOR data
	cbor1 := envelope1.Bytes()
	cbor2 := envelope2.Bytes()
	cbor3 := envelope3.Bytes()

	concatenated := append(cbor1, cbor2...)
	concatenated = append(concatenated, cbor3...)

	t.Logf("Processing %d bytes of concatenated CBOR data", len(concatenated))

	// Process all at once
	err := decoder.ProcessChunk(concatenated)
	require.NoError(t, err)

	// Should have processed all three envelopes
	require.Len(t, processedEnvelopes, 3)
	require.Equal(t, envelope1.Epoch, processedEnvelopes[0].Epoch)
	require.Equal(t, envelope2.Epoch, processedEnvelopes[1].Epoch)
	require.Equal(t, envelope3.Epoch, processedEnvelopes[2].Epoch)

	t.Log("Streaming decoder works with concatenated CBOR data")
}

// TestStreamingDecoderPartialChunks tests the streaming decoder with partial chunks
func TestStreamingDecoderPartialChunks(t *testing.T) {
	nikeScheme := setupNikeScheme(t)

	var processedEnvelopes []*common.CourierEnvelope
	handleEnvelope := createBasicEnvelopeHandler(t, &processedEnvelopes)
	decoder := NewStreamingCBORDecoder(handleEnvelope)

	// Create multiple envelopes
	envelope1 := createTestEnvelope(t, []byte(testMessage1), nikeScheme)
	envelope2 := createTestEnvelope(t, []byte(testMessage2), nikeScheme)

	// Concatenate CBOR data
	cbor1 := envelope1.Bytes()
	cbor2 := envelope2.Bytes()
	concatenated := append(cbor1, cbor2...)

	t.Logf("Total data size: %d bytes", len(concatenated))
	t.Logf(logEnvelopeSize, 1, len(cbor1))
	t.Logf(logEnvelopeSize, 2, len(cbor2))

	// Process in small chunks
	chunkSize := 50
	for i := 0; i < len(concatenated); i += chunkSize {
		end := i + chunkSize
		if end > len(concatenated) {
			end = len(concatenated)
		}
		chunk := concatenated[i:end]

		t.Logf("Processing chunk %d-%d (%d bytes)", i, end-1, len(chunk))
		err := decoder.ProcessChunk(chunk)
		require.NoError(t, err)
		t.Logf("After chunk: processed %d envelopes", len(processedEnvelopes))
	}

	// Finalize to process any remaining data
	err := decoder.Finalize()
	require.NoError(t, err)

	// Should have processed both envelopes
	require.Len(t, processedEnvelopes, 2)
	require.Equal(t, envelope1.Epoch, processedEnvelopes[0].Epoch)
	require.Equal(t, envelope2.Epoch, processedEnvelopes[1].Epoch)

	t.Log("Streaming decoder works with partial chunks")
}

// TestStreamingDecoderBufferBehavior tests the internal buffer behavior
func TestStreamingDecoderBufferBehavior(t *testing.T) {
	nikeScheme := setupNikeScheme(t)

	var processedEnvelopes []*common.CourierEnvelope
	var bufferLengths []int

	handleEnvelope := createBasicEnvelopeHandler(t, &processedEnvelopes)
	decoder := NewStreamingCBORDecoder(handleEnvelope)

	// Create a test envelope
	envelope := createTestEnvelope(t, []byte("test message"), nikeScheme)
	cborData := envelope.Bytes()

	t.Logf("Envelope CBOR size: %d bytes", len(cborData))

	// Check buffer length before processing
	bufferLengths = append(bufferLengths, decoder.buffer.Len())
	t.Logf("Buffer length before: %d", decoder.buffer.Len())

	// Process the envelope
	err := decoder.ProcessChunk(cborData)
	require.NoError(t, err)

	// Check buffer length after processing
	bufferLengths = append(bufferLengths, decoder.buffer.Len())
	t.Logf("Buffer length after: %d", decoder.buffer.Len())

	// Should have processed one envelope
	require.Len(t, processedEnvelopes, 1)

	// Buffer should be empty after processing complete envelope
	require.Equal(t, 0, decoder.buffer.Len(), "Buffer should be empty after processing complete envelope")

	t.Log("Buffer behavior test passed")
}

// TestStreamingDecoderWithInvalidData tests how the decoder handles invalid CBOR data
func TestStreamingDecoderWithInvalidData(t *testing.T) {
	var processedEnvelopes []*common.CourierEnvelope
	handleEnvelope := createSilentEnvelopeHandler(&processedEnvelopes)
	decoder := NewStreamingCBORDecoder(handleEnvelope)

	// Test with completely invalid data
	invalidData := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	err := decoder.ProcessChunk(invalidData)
	// Should not error, just wait for more data
	require.NoError(t, err)
	require.Len(t, processedEnvelopes, 0)

	// Test with partial valid CBOR that's incomplete
	partialCBOR := []byte{0x82, 0x01} // Start of CBOR array but incomplete
	err = decoder.ProcessChunk(partialCBOR)
	require.NoError(t, err)
	require.Len(t, processedEnvelopes, 0)

	t.Log("Invalid data handling test passed")
}

// TestStreamingDecoderProgressIssue specifically tests the "made no progress" scenario
func TestStreamingDecoderProgressIssue(t *testing.T) {
	nikeScheme := setupNikeScheme(t)

	var processedEnvelopes []*common.CourierEnvelope
	var progressCalls []string

	handleEnvelope := createProgressTrackingHandler(t, &processedEnvelopes, &progressCalls)

	// Create a custom decoder to monitor buffer changes
	decoder := NewStreamingCBORDecoder(handleEnvelope)

	// Create test envelopes
	envelope1 := createTestEnvelope(t, []byte(testMessage1), nikeScheme)
	envelope2 := createTestEnvelope(t, []byte(testMessage2), nikeScheme)

	cbor1 := envelope1.Bytes()
	cbor2 := envelope2.Bytes()

	t.Logf(logEnvelopeSize, 1, len(cbor1))
	t.Logf(logEnvelopeSize, 2, len(cbor2))

	// Test scenario: concatenated data that might cause progress issues
	concatenated := append(cbor1, cbor2...)

	// Process in a way that might trigger the "no progress" issue
	// Add data to buffer
	initialLen := decoder.buffer.Len()
	decoder.buffer.Write(concatenated)
	afterWriteLen := decoder.buffer.Len()

	t.Logf("Buffer length: initial=%d, after_write=%d", initialLen, afterWriteLen)

	// Now try to process available envelopes manually
	err := decoder.processAvailableEnvelopes()
	require.NoError(t, err)

	finalLen := decoder.buffer.Len()
	t.Logf("Buffer length after processing: %d", finalLen)
	t.Logf("Processed %d envelopes", len(processedEnvelopes))

	// Should have processed both envelopes
	require.Len(t, processedEnvelopes, 2)
	require.Equal(t, 0, finalLen, "Buffer should be empty after processing all data")

	t.Log("Progress issue test passed")
}

// TestStreamingDecoderLargeData tests with larger amounts of data
func TestStreamingDecoderLargeData(t *testing.T) {
	nikeScheme := setupNikeScheme(t)

	var processedEnvelopes []*common.CourierEnvelope
	handleEnvelope := createSilentEnvelopeHandler(&processedEnvelopes)
	decoder := NewStreamingCBORDecoder(handleEnvelope)

	// Create many envelopes
	numEnvelopes := 10
	var allCBOR []byte

	for i := 0; i < numEnvelopes; i++ {
		envelope := createTestEnvelope(t, []byte(fmt.Sprintf("message %d", i)), nikeScheme)
		cborData := envelope.Bytes()
		allCBOR = append(allCBOR, cborData...)
	}

	t.Logf("Total CBOR data size: %d bytes for %d envelopes", len(allCBOR), numEnvelopes)

	// Process in chunks
	chunkSize := 100
	for i := 0; i < len(allCBOR); i += chunkSize {
		end := i + chunkSize
		if end > len(allCBOR) {
			end = len(allCBOR)
		}
		chunk := allCBOR[i:end]

		err := decoder.ProcessChunk(chunk)
		require.NoError(t, err)
	}

	// Finalize
	err := decoder.Finalize()
	require.NoError(t, err)

	// Should have processed all envelopes
	require.Len(t, processedEnvelopes, numEnvelopes)

	t.Logf("Successfully processed %d envelopes from large data", len(processedEnvelopes))
}

// TestStreamingDecoderBufferConsumption tests exactly how the buffer is consumed
func TestStreamingDecoderBufferConsumption(t *testing.T) {
	nikeScheme := setupNikeScheme(t)

	var processedEnvelopes []*common.CourierEnvelope
	handleEnvelope := createBasicEnvelopeHandler(t, &processedEnvelopes)
	decoder := NewStreamingCBORDecoder(handleEnvelope)

	// Create two different envelopes
	envelope1 := createTestEnvelope(t, []byte(testMessage1), nikeScheme)
	envelope2 := createTestEnvelope(t, []byte(testMessage2), nikeScheme)

	cbor1 := envelope1.Bytes()
	cbor2 := envelope2.Bytes()

	t.Logf(logEnvelopeSize, 1, len(cbor1))
	t.Logf(logEnvelopeSize, 2, len(cbor2))

	// Concatenate the data
	concatenated := append(cbor1, cbor2...)
	t.Logf("Total concatenated size: %d bytes", len(concatenated))

	// Add all data to buffer at once
	decoder.buffer.Write(concatenated)
	t.Logf("Buffer length after write: %d", decoder.buffer.Len())

	// Try to decode first envelope manually
	var env1 common.CourierEnvelope
	err := decoder.decoder.Decode(&env1)
	require.NoError(t, err)
	t.Logf("After decoding envelope 1, buffer length: %d", decoder.buffer.Len())

	// Try to decode second envelope manually
	var env2 common.CourierEnvelope
	err = decoder.decoder.Decode(&env2)
	if err != nil {
		t.Logf("Failed to decode envelope 2: %s", err)
		t.Logf("Buffer length when decode failed: %d", decoder.buffer.Len())

		// Let's see what's in the buffer
		remaining := decoder.buffer.Bytes()
		t.Logf("Remaining buffer content: %x", remaining[:min(50, len(remaining))])
	} else {
		t.Logf("Successfully decoded envelope 2, buffer length: %d", decoder.buffer.Len())
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestStreamingDecoderDetailedBuffer tests the buffer behavior in detail
func TestStreamingDecoderDetailedBuffer(t *testing.T) {
	nikeScheme := setupNikeScheme(t)

	// Create two different envelopes
	envelope1 := createTestEnvelope(t, []byte(testMessage1), nikeScheme)
	envelope2 := createTestEnvelope(t, []byte(testMessage2), nikeScheme)

	cbor1 := envelope1.Bytes()
	cbor2 := envelope2.Bytes()

	t.Logf(logEnvelopeSize, 1, len(cbor1))
	t.Logf(logEnvelopeSize, 2, len(cbor2))

	// Test 1: Decode each envelope separately
	t.Log("=== Test 1: Separate decoding ===")
	env1, err := common.CourierEnvelopeFromBytes(cbor1)
	require.NoError(t, err)
	t.Logf("Envelope 1 decoded successfully, epoch: %d", env1.Epoch)

	env2, err := common.CourierEnvelopeFromBytes(cbor2)
	require.NoError(t, err)
	t.Logf("Envelope 2 decoded successfully, epoch: %d", env2.Epoch)

	// Test 2: Decode from concatenated data using bytes.Buffer and CBOR decoder
	t.Log("=== Test 2: Concatenated decoding with buffer ===")
	concatenated := append(cbor1, cbor2...)

	buffer := bytes.NewBuffer(concatenated)
	decMode, err := cbor.DecOptions{}.DecMode()
	require.NoError(t, err)
	decoder := decMode.NewDecoder(buffer)

	t.Logf("Initial buffer length: %d", buffer.Len())

	// Decode first envelope
	var env1Concat common.CourierEnvelope
	err = decoder.Decode(&env1Concat)
	require.NoError(t, err)
	t.Logf("After decoding envelope 1: buffer length = %d, epoch = %d", buffer.Len(), env1Concat.Epoch)

	// Decode second envelope
	var env2Concat common.CourierEnvelope
	err = decoder.Decode(&env2Concat)
	require.NoError(t, err)
	t.Logf("After decoding envelope 2: buffer length = %d, epoch = %d", buffer.Len(), env2Concat.Epoch)

	// Test 3: Use the streaming decoder's processAvailableEnvelopes method
	t.Log("=== Test 3: Streaming decoder processAvailableEnvelopes ===")
	var processedEnvelopes []*common.CourierEnvelope
	handleEnvelope := createBasicEnvelopeHandler(t, &processedEnvelopes)

	streamingDecoder := NewStreamingCBORDecoder(handleEnvelope)
	streamingDecoder.buffer.Write(concatenated)
	t.Logf("Streaming decoder buffer length before processing: %d", streamingDecoder.buffer.Len())

	err = streamingDecoder.processAvailableEnvelopes()
	require.NoError(t, err)
	t.Logf("Streaming decoder buffer length after processing: %d", streamingDecoder.buffer.Len())
	t.Logf("Number of processed envelopes: %d", len(processedEnvelopes))
}
