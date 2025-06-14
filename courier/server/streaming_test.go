package server

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/replica/common"
)

// TestCopyCommandStreaming tests the copy command's streaming CBOR processing
func TestStreamingCBORDecoder(t *testing.T) {
	// Create test CourierEnvelopes
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	envelope1 := createTestEnvelope(t, []byte("First message"), nikeScheme)
	envelope2 := createTestEnvelope(t, []byte("Second message"), nikeScheme)
	envelope3 := createTestEnvelope(t, []byte("Third message"), nikeScheme)

	// Serialize the envelopes to CBOR
	envelope1Bytes := envelope1.Bytes()
	envelope2Bytes := envelope2.Bytes()
	envelope3Bytes := envelope3.Bytes()

	t.Logf("Envelope sizes: %d, %d, %d bytes", len(envelope1Bytes), len(envelope2Bytes), len(envelope3Bytes))

	// Track processed envelopes
	var processedEnvelopes []*common.CourierEnvelope
	handleEnvelope := func(envelope *common.CourierEnvelope) {
		processedEnvelopes = append(processedEnvelopes, envelope)
	}

	// Create streaming decoder
	decoder := NewStreamingCBORDecoder(handleEnvelope)

	// Test 1: Process complete envelopes in chunks
	t.Run("CompleteEnvelopes", func(t *testing.T) {
		processedEnvelopes = nil // Reset

		// Feed envelope1 completely
		err := decoder.ProcessChunk(envelope1Bytes)
		require.NoError(t, err)
		require.Len(t, processedEnvelopes, 1, "Should have processed envelope1")

		// Feed envelope2 completely
		err = decoder.ProcessChunk(envelope2Bytes)
		require.NoError(t, err)
		require.Len(t, processedEnvelopes, 2, "Should have processed envelope1 and envelope2")

		// Feed envelope3 completely
		err = decoder.ProcessChunk(envelope3Bytes)
		require.NoError(t, err)
		require.Len(t, processedEnvelopes, 3, "Should have processed all three envelopes")

		// Verify envelope contents
		require.Equal(t, envelope1.Epoch, processedEnvelopes[0].Epoch)
		require.Equal(t, envelope2.Epoch, processedEnvelopes[1].Epoch)
		require.Equal(t, envelope3.Epoch, processedEnvelopes[2].Epoch)
	})

	// Test 2: Process partial chunks (simulating box boundaries)
	t.Run("PartialChunks", func(t *testing.T) {
		processedEnvelopes = nil                          // Reset
		decoder = NewStreamingCBORDecoder(handleEnvelope) // Fresh decoder

		// Concatenate all envelope data
		allData := append(envelope1Bytes, envelope2Bytes...)
		allData = append(allData, envelope3Bytes...)

		// Feed data in small chunks (simulating box payload boundaries)
		chunkSize := 50
		for i := 0; i < len(allData); i += chunkSize {
			end := i + chunkSize
			if end > len(allData) {
				end = len(allData)
			}
			chunk := allData[i:end]

			err := decoder.ProcessChunk(chunk)
			require.NoError(t, err)
			t.Logf("After chunk %d-%d: processed %d envelopes", i, end, len(processedEnvelopes))
		}

		// Finalize to process any remaining data
		err := decoder.Finalize()
		require.NoError(t, err)

		// Should have processed all three envelopes
		require.Len(t, processedEnvelopes, 3, "Should have processed all three envelopes from partial chunks")

		// Verify envelope contents
		require.Equal(t, envelope1.Epoch, processedEnvelopes[0].Epoch)
		require.Equal(t, envelope2.Epoch, processedEnvelopes[1].Epoch)
		require.Equal(t, envelope3.Epoch, processedEnvelopes[2].Epoch)
	})

	t.Log("Copy command streaming test completed successfully")
}

func createTestEnvelope(t *testing.T, payload []byte, nikeScheme nike.Scheme) *common.CourierEnvelope {
	// Generate ephemeral key pair
	ephemeralPub, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	ephemeralPubBytes := ephemeralPub.Bytes()

	// Create DEK arrays
	dek1 := &[mkem.DEKSize]byte{}
	dek2 := &[mkem.DEKSize]byte{}
	_, err = rand.Reader.Read(dek1[:])
	require.NoError(t, err)
	_, err = rand.Reader.Read(dek2[:])
	require.NoError(t, err)

	// Use different epochs to distinguish envelopes
	epoch := uint64(12345 + len(payload)) // Simple way to make epochs different

	return &common.CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1},
		DEK:                  [2]*[mkem.DEKSize]byte{dek1, dek2},
		ReplyIndex:           0,
		Epoch:                epoch,
		SenderEPubKey:        ephemeralPubBytes,
		IsRead:               false,
		Ciphertext:           payload,
	}
}
