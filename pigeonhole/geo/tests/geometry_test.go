// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/pigeonhole"
	pigeonholegeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
)

// Test log message constants to avoid duplication
const (
	logSphinxUserForwardPayloadLength = "Sphinx UserForwardPayloadLength: %d"
)

func TestGeometryUseCase1FromBoxPayloadLength(t *testing.T) {
	// Use Case 1: Given BoxPayloadLength, derive all envelope sizes
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	boxPayloadLength := 1000
	g := pigeonholegeo.NewGeometry(boxPayloadLength, nikeScheme)

	require.NoError(t, g.Validate())
	require.Equal(t, boxPayloadLength, g.MaxPlaintextPayloadLength)
	require.Equal(t, "x25519", g.NIKEName)
	require.Equal(t, "Ed25519", g.SignatureSchemeName)

	// All envelope sizes should be calculated and positive
	require.Greater(t, g.CourierQueryReadLength, 0)
	require.Greater(t, g.CourierQueryWriteLength, 0)
	require.Greater(t, g.CourierQueryReplyReadLength, 0)
	require.Greater(t, g.CourierQueryReplyWriteLength, 0)

	// Write operations should generally be larger than read operations
	require.Greater(t, g.CourierQueryWriteLength, g.CourierQueryReadLength)
	require.Greater(t, g.CourierQueryReplyReadLength, g.CourierQueryReplyWriteLength)

	t.Logf("Geometry for BoxPayloadLength=%d:\n%s", boxPayloadLength, g.String())
}

func TestGeometryUseCase2ToSphinxGeometry(t *testing.T) {
	// Use Case 2: Given precomputed Geometry, derive accommodating Sphinx Geometry
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	// Create a pigeonhole geometry
	pigeonholeGeo := pigeonholegeo.NewGeometry(500, nikeScheme)
	require.NoError(t, pigeonholeGeo.Validate())

	// Derive a Sphinx geometry that can accommodate it
	sphinxGeo := pigeonholeGeo.ToSphinxGeometry(5, true) // 5 hops, with SURB
	require.NoError(t, sphinxGeo.Validate())

	// The Sphinx geometry should be able to fit our largest envelope
	maxEnvelopeSize := max(
		pigeonholeGeo.CourierQueryReadLength,
		pigeonholeGeo.CourierQueryWriteLength,
		pigeonholeGeo.CourierQueryReplyReadLength,
		pigeonholeGeo.CourierQueryReplyWriteLength,
	)

	require.GreaterOrEqual(t, sphinxGeo.UserForwardPayloadLength, maxEnvelopeSize)

	t.Logf("Pigeonhole max envelope size: %d", maxEnvelopeSize)
	t.Logf(logSphinxUserForwardPayloadLength, sphinxGeo.UserForwardPayloadLength)
	t.Logf("Sphinx PacketLength: %d", sphinxGeo.PacketLength)
}

func TestGeometryUseCase3FromSphinxGeometry(t *testing.T) {
	// Use Case 3: Given Sphinx Geometry constraint, derive optimal Geometry
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	// Create a Sphinx geometry with limited space
	sphinxGeo := geo.GeometryFromUserForwardPayloadLength(nikeScheme, 2000, true, 5)
	require.NoError(t, sphinxGeo.Validate())

	// Derive the optimal pigeonhole geometry that maximizes usage of the Sphinx space
	pigeonholeGeo, err := pigeonholegeo.NewGeometryFromSphinx(sphinxGeo, nikeScheme)
	require.NoError(t, err)
	require.NoError(t, pigeonholeGeo.Validate())

	// The largest envelope should fit within the Sphinx constraint
	maxEnvelopeSize := max(
		pigeonholeGeo.CourierQueryReadLength,
		pigeonholeGeo.CourierQueryWriteLength,
		pigeonholeGeo.CourierQueryReplyReadLength,
		pigeonholeGeo.CourierQueryReplyWriteLength,
	)

	require.LessOrEqual(t, maxEnvelopeSize, sphinxGeo.UserForwardPayloadLength)

	// The MaxPlaintextPayloadLength should be optimized (not too small)
	require.Greater(t, pigeonholeGeo.MaxPlaintextPayloadLength, 100) // Should find a reasonable size

	t.Logf(logSphinxUserForwardPayloadLength, sphinxGeo.UserForwardPayloadLength)
	t.Logf("Optimal MaxPlaintextPayloadLength: %d", pigeonholeGeo.MaxPlaintextPayloadLength)
	t.Logf("Max envelope size: %d", maxEnvelopeSize)
	t.Logf("Space utilization: %.1f%%", float64(maxEnvelopeSize)*100/float64(sphinxGeo.UserForwardPayloadLength))
}

func TestGeometryPrecisionComparison(t *testing.T) {
	// Test that demonstrates the precision and determinism of trunnel's fixed binary format
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	testCases := []int{100, 500, 1000, 2000, 5000}

	for _, boxPayloadLength := range testCases {
		t.Run(fmt.Sprintf("BoxPayloadLength_%d", boxPayloadLength), func(t *testing.T) {
			g := pigeonholegeo.NewGeometry(boxPayloadLength, nikeScheme)
			require.NoError(t, g.Validate())

			// With trunnel, calculations should be perfectly deterministic
			g2 := pigeonholegeo.NewGeometry(boxPayloadLength, nikeScheme)
			require.Equal(t, g.CourierQueryReadLength, g2.CourierQueryReadLength)
			require.Equal(t, g.CourierQueryWriteLength, g2.CourierQueryWriteLength)
			require.Equal(t, g.CourierQueryReplyReadLength, g2.CourierQueryReplyReadLength)
			require.Equal(t, g.CourierQueryReplyWriteLength, g2.CourierQueryReplyWriteLength)

			t.Logf("BoxPayloadLength=%d: Read=%d, Write=%d, ReplyRead=%d, ReplyWrite=%d",
				boxPayloadLength,
				g.CourierQueryReadLength,
				g.CourierQueryWriteLength,
				g.CourierQueryReplyReadLength,
				g.CourierQueryReplyWriteLength)
		})
	}
}

func TestGeometryBidirectionalSizing(t *testing.T) {
	// Test the bidirectional sizing capability
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	// Start with a BoxPayloadLength
	originalBoxPayloadLength := 1000
	pigeonholeGeo1 := pigeonholegeo.NewGeometry(originalBoxPayloadLength, nikeScheme)

	// Convert to Sphinx geometry
	sphinxGeo := pigeonholeGeo1.ToSphinxGeometry(5, true)

	// Convert back to pigeonhole geometry
	pigeonholeGeo2, err := pigeonholegeo.NewGeometryFromSphinx(sphinxGeo, nikeScheme)
	require.NoError(t, err)

	t.Logf("Original MaxPlaintextPayloadLength: %d", originalBoxPayloadLength)
	t.Logf("Round-trip MaxPlaintextPayloadLength: %d", pigeonholeGeo2.MaxPlaintextPayloadLength)
	t.Logf(logSphinxUserForwardPayloadLength, sphinxGeo.UserForwardPayloadLength)

	// Calculate the max envelope size from the original geometry
	maxEnvelopeSize1 := max(
		pigeonholeGeo1.CourierQueryReadLength,
		pigeonholeGeo1.CourierQueryWriteLength,
		pigeonholeGeo1.CourierQueryReplyReadLength,
		pigeonholeGeo1.CourierQueryReplyWriteLength,
	)

	// Calculate the max envelope size from the round-trip geometry
	maxEnvelopeSize2 := max(
		pigeonholeGeo2.CourierQueryReadLength,
		pigeonholeGeo2.CourierQueryWriteLength,
		pigeonholeGeo2.CourierQueryReplyReadLength,
		pigeonholeGeo2.CourierQueryReplyWriteLength,
	)

	t.Logf("Original max envelope size: %d", maxEnvelopeSize1)
	t.Logf("Round-trip max envelope size: %d", maxEnvelopeSize2)
	t.Logf("Difference in MaxPlaintextPayloadLength: %d", pigeonholeGeo2.MaxPlaintextPayloadLength-originalBoxPayloadLength)

	// The round-trip should give us a MaxPlaintextPayloadLength that's close to the original
	// A small loss (few bytes) is acceptable due to overhead calculations
	require.GreaterOrEqual(t, pigeonholeGeo2.MaxPlaintextPayloadLength, originalBoxPayloadLength-10)
}

func TestGeometryPrecisePredictions(t *testing.T) {
	// Test that geometry predictions exactly match actual serialized message sizes
	// This test creates real messages like the integration tests do
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	g := pigeonholegeo.NewGeometry(4559, nikeScheme) // Use the same BoxPayloadLength as integration test
	require.NoError(t, g.Validate())

	// Create BACAP keys like integration tests
	aliceOwner, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	aliceStatefulWriter, err := bacap.NewStatefulWriter(aliceOwner, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)

	// Create MKEM keys for replicas like integration tests
	mkemNikeScheme := mkem.NewScheme(nikeScheme)
	replicaPublicKey1, replicaPrivateKey1, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	replicaPublicKey2, replicaPrivateKey2, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	_ = replicaPrivateKey1 // Avoid unused variable warning
	_ = replicaPrivateKey2 // Avoid unused variable warning
	replicaPubKeys := []nike.PublicKey{
		replicaPublicKey1,
		replicaPublicKey2,
	}

	t.Run("CourierQueryWrite", func(t *testing.T) {
		// Create a real test message like integration tests
		testMessage := []byte("Hello, Bob! This is a test message for geometry validation.")

		// Create padded payload with length prefix for BACAP (like integration tests)
		paddedPayload, err := pigeonhole.CreatePaddedPayload(testMessage, g.MaxPlaintextPayloadLength+4)
		require.NoError(t, err)

		// BACAP encrypt the payload (like integration tests)
		boxID, ciphertext, sigraw, err := aliceStatefulWriter.EncryptNext(paddedPayload)
		require.NoError(t, err)

		sig := [bacap.SignatureSize]byte{}
		copy(sig[:], sigraw)

		// Create ReplicaWrite like integration tests
		writeRequest := pigeonhole.ReplicaWrite{
			BoxID:      boxID,
			Signature:  sig,
			PayloadLen: uint32(len(ciphertext)),
			Payload:    ciphertext,
		}

		// Create ReplicaInnerMessage like integration tests
		msg := &pigeonhole.ReplicaInnerMessage{
			MessageType: 1, // 1 = write, 0 = read
			WriteMsg:    &writeRequest,
		}

		// MKEM encrypt the inner message like integration tests
		mkemPrivateKey, mkemCiphertext := mkemNikeScheme.Encapsulate(replicaPubKeys, msg.Bytes())
		mkemPublicKey := mkemPrivateKey.Public()
		senderPubkeyBytes := mkemPublicKey.Bytes()

		// Create CourierEnvelope like integration tests
		envelope := &pigeonhole.CourierEnvelope{
			IntermediateReplicas: [2]uint8{0, 1},
			Dek1:                 *mkemCiphertext.DEKCiphertexts[0],
			Dek2:                 *mkemCiphertext.DEKCiphertexts[1],
			ReplyIndex:           0,
			Epoch:                1, // Use test epoch
			SenderPubkeyLen:      uint16(len(senderPubkeyBytes)),
			SenderPubkey:         senderPubkeyBytes,
			CiphertextLen:        uint32(len(mkemCiphertext.Envelope)),
			Ciphertext:           mkemCiphertext.Envelope,
		}

		// Create CourierQuery like integration tests
		query := &pigeonhole.CourierQuery{
			QueryType: 0, // 0 = envelope
			Envelope:  envelope,
		}

		// Test the actual serialized size against geometry prediction
		serialized := query.Bytes()
		actualSize := len(serialized)
		predictedSize := g.CourierQueryWriteLength

		t.Logf("Test message: %s", string(testMessage))
		t.Logf("MaxPlaintextPayloadLength: %d bytes", g.MaxPlaintextPayloadLength)
		t.Logf("Padded payload size: %d bytes", len(paddedPayload))
		t.Logf("BACAP ciphertext size: %d bytes", len(ciphertext))
		t.Logf("ReplicaWrite size: %d bytes", len(writeRequest.Bytes()))
		t.Logf("ReplicaInnerMessage size: %d bytes", len(msg.Bytes()))
		t.Logf("MKEM ciphertext size: %d bytes", len(mkemCiphertext.Envelope))
		t.Logf("CourierEnvelope size: %d bytes", len(envelope.Bytes()))

		// Calculate the actual CourierQuery wrapper overhead
		envelopeSize := len(envelope.Bytes())
		courierQueryOverhead := actualSize - envelopeSize
		t.Logf("Actual CourierQuery wrapper overhead: %d bytes", courierQueryOverhead)

		// Calculate what the CourierEnvelope overhead should be
		mkemCiphertextSize := len(mkemCiphertext.Envelope)
		actualCourierEnvelopeOverhead := envelopeSize - mkemCiphertextSize
		t.Logf("MKEM ciphertext size: %d, CourierEnvelope size: %d", mkemCiphertextSize, envelopeSize)
		t.Logf("Actual CourierEnvelope overhead: %d bytes", actualCourierEnvelopeOverhead)

		// Check what our calculation predicts
		senderPubkeySize := len(senderPubkeyBytes)

		// Calculate what our function should return
		const intermediateReplicasSize = 2 // [2]uint8
		const dek1Size = 60                // [60]uint8
		const dek2Size = 60                // [60]uint8
		const replyIndexSize = 1           // uint8
		const epochSize = 8                // uint64
		const senderPubkeyLenSize = 2      // uint16
		const ciphertextLenSize = 4        // uint32

		expectedFixedOverhead := intermediateReplicasSize + dek1Size + dek2Size +
			replyIndexSize + epochSize + senderPubkeyLenSize + ciphertextLenSize
		expectedTotalOverhead := expectedFixedOverhead + senderPubkeySize

		t.Logf("Sender pubkey size: %d", senderPubkeySize)
		t.Logf("Expected fixed overhead: %d", expectedFixedOverhead)
		t.Logf("Expected total overhead: %d", expectedTotalOverhead)

		t.Logf("Predicted CourierQueryWriteLength: %d bytes", predictedSize)
		t.Logf("Actual serialized size: %d bytes", actualSize)
		t.Logf("Difference: %d bytes", actualSize-predictedSize)

		// The geometry prediction must be exact
		require.Equal(t, predictedSize, actualSize,
			"Geometry prediction for CourierQueryWriteLength must be exact")
	})

	t.Run("LayerByLayerOverheadAnalysis", func(t *testing.T) {
		// Test each message layer individually to pinpoint calculation errors
		// This follows the pattern from the old geometry tests

		testMessage := []byte("Test message for layer analysis")

		// Layer 1: BACAP encryption (innermost layer)
		paddedPayload, err := pigeonhole.CreatePaddedPayload(testMessage, g.MaxPlaintextPayloadLength+4)
		require.NoError(t, err)

		boxID, bacapCiphertext, sigraw, err := aliceStatefulWriter.EncryptNext(paddedPayload)
		require.NoError(t, err)

		bacapOverhead := len(bacapCiphertext) - len(paddedPayload)
		expectedBACAPOverhead := 16 // bacapEncryptionOverhead constant

		t.Logf("Layer 1 - BACAP:")
		t.Logf("  Padded payload: %d bytes", len(paddedPayload))
		t.Logf("  BACAP ciphertext: %d bytes", len(bacapCiphertext))
		t.Logf("  Actual BACAP overhead: %d bytes", bacapOverhead)
		t.Logf("  Expected BACAP overhead: %d bytes", expectedBACAPOverhead)
		require.Equal(t, expectedBACAPOverhead, bacapOverhead, "BACAP overhead should match constant")

		// Layer 2: ReplicaWrite (contains BACAP ciphertext)
		sig := [bacap.SignatureSize]byte{}
		copy(sig[:], sigraw)

		writeRequest := pigeonhole.ReplicaWrite{
			BoxID:      boxID,
			Signature:  sig,
			PayloadLen: uint32(len(bacapCiphertext)),
			Payload:    bacapCiphertext,
		}

		replicaWriteBytes := writeRequest.Bytes()
		replicaWriteOverhead := len(replicaWriteBytes) - len(bacapCiphertext)
		expectedReplicaWriteOverhead := bacap.BoxIDSize + bacap.SignatureSize + 4 // BoxID + Signature + PayloadLen

		t.Logf("Layer 2 - ReplicaWrite:")
		t.Logf("  BACAP ciphertext: %d bytes", len(bacapCiphertext))
		t.Logf("  ReplicaWrite total: %d bytes", len(replicaWriteBytes))
		t.Logf("  Actual ReplicaWrite overhead: %d bytes", replicaWriteOverhead)
		t.Logf("  Expected ReplicaWrite overhead: %d bytes", expectedReplicaWriteOverhead)
		require.Equal(t, expectedReplicaWriteOverhead, replicaWriteOverhead, "ReplicaWrite overhead should match calculation")

		// Layer 3: ReplicaInnerMessage (contains ReplicaWrite)
		msg := &pigeonhole.ReplicaInnerMessage{
			MessageType: 1, // 1 = write
			WriteMsg:    &writeRequest,
		}

		replicaInnerBytes := msg.Bytes()
		replicaInnerOverhead := len(replicaInnerBytes) - len(replicaWriteBytes)
		expectedReplicaInnerOverhead := 1 // MessageType field

		t.Logf("Layer 3 - ReplicaInnerMessage:")
		t.Logf("  ReplicaWrite: %d bytes", len(replicaWriteBytes))
		t.Logf("  ReplicaInnerMessage total: %d bytes", len(replicaInnerBytes))
		t.Logf("  Actual ReplicaInnerMessage overhead: %d bytes", replicaInnerOverhead)
		t.Logf("  Expected ReplicaInnerMessage overhead: %d bytes", expectedReplicaInnerOverhead)
		require.Equal(t, expectedReplicaInnerOverhead, replicaInnerOverhead, "ReplicaInnerMessage overhead should match calculation")

		// Layer 4: MKEM encryption (encrypts ReplicaInnerMessage)
		mkemPrivateKey, mkemCiphertext := mkemNikeScheme.Encapsulate(replicaPubKeys, replicaInnerBytes)
		mkemOverhead := len(mkemCiphertext.Envelope) - len(replicaInnerBytes)
		expectedMKEMOverhead := 28 // mkemEncryptionOverhead constant

		t.Logf("Layer 4 - MKEM:")
		t.Logf("  ReplicaInnerMessage: %d bytes", len(replicaInnerBytes))
		t.Logf("  MKEM ciphertext: %d bytes", len(mkemCiphertext.Envelope))
		t.Logf("  Actual MKEM overhead: %d bytes", mkemOverhead)
		t.Logf("  Expected MKEM overhead: %d bytes", expectedMKEMOverhead)
		require.Equal(t, expectedMKEMOverhead, mkemOverhead, "MKEM overhead should match constant")

		// Layer 5: CourierEnvelope (contains MKEM ciphertext)
		mkemPublicKey := mkemPrivateKey.Public()
		senderPubkeyBytes := mkemPublicKey.Bytes()

		envelope := &pigeonhole.CourierEnvelope{
			IntermediateReplicas: [2]uint8{0, 1},
			Dek1:                 *mkemCiphertext.DEKCiphertexts[0],
			Dek2:                 *mkemCiphertext.DEKCiphertexts[1],
			ReplyIndex:           0,
			Epoch:                1,
			SenderPubkeyLen:      uint16(len(senderPubkeyBytes)),
			SenderPubkey:         senderPubkeyBytes,
			CiphertextLen:        uint32(len(mkemCiphertext.Envelope)),
			Ciphertext:           mkemCiphertext.Envelope,
		}

		envelopeBytes := envelope.Bytes()
		courierEnvelopeOverhead := len(envelopeBytes) - len(mkemCiphertext.Envelope)

		// Calculate expected CourierEnvelope overhead using our constants
		const intermediateReplicasSize = 2 // [2]uint8
		const dek1Size = 60                // [60]uint8
		const dek2Size = 60                // [60]uint8
		const replyIndexSize = 1           // uint8
		const epochSize = 8                // uint64
		const senderPubkeyLenSize = 2      // uint16
		const ciphertextLenSize = 4        // uint32

		expectedCourierEnvelopeOverhead := intermediateReplicasSize + dek1Size + dek2Size +
			replyIndexSize + epochSize + senderPubkeyLenSize + ciphertextLenSize + len(senderPubkeyBytes)

		t.Logf("Layer 5 - CourierEnvelope:")
		t.Logf("  MKEM ciphertext: %d bytes", len(mkemCiphertext.Envelope))
		t.Logf("  Sender pubkey: %d bytes", len(senderPubkeyBytes))
		t.Logf("  CourierEnvelope total: %d bytes", len(envelopeBytes))
		t.Logf("  Actual CourierEnvelope overhead: %d bytes", courierEnvelopeOverhead)
		t.Logf("  Expected CourierEnvelope overhead: %d bytes", expectedCourierEnvelopeOverhead)
		require.Equal(t, expectedCourierEnvelopeOverhead, courierEnvelopeOverhead, "CourierEnvelope overhead should match calculation")

		// Layer 6: CourierQuery (outermost layer)
		query := &pigeonhole.CourierQuery{
			QueryType: 0, // 0 = envelope
			Envelope:  envelope,
		}

		queryBytes := query.Bytes()
		courierQueryOverhead := len(queryBytes) - len(envelopeBytes)
		expectedCourierQueryOverhead := 1 // QueryType (1) - union discriminator, no envelope length prefix in trunnel

		t.Logf("Layer 6 - CourierQuery:")
		t.Logf("  CourierEnvelope: %d bytes", len(envelopeBytes))
		t.Logf("  CourierQuery total: %d bytes", len(queryBytes))
		t.Logf("  Actual CourierQuery overhead: %d bytes", courierQueryOverhead)
		t.Logf("  Expected CourierQuery overhead: %d bytes", expectedCourierQueryOverhead)
		require.Equal(t, expectedCourierQueryOverhead, courierQueryOverhead, "CourierQuery overhead should match calculation")

		// Final verification: total size should match geometry prediction
		totalActualSize := len(queryBytes)
		geometryPrediction := g.CourierQueryWriteLength

		t.Logf("Final verification:")
		t.Logf("  Total actual size: %d bytes", totalActualSize)
		t.Logf("  Geometry prediction: %d bytes", geometryPrediction)
		t.Logf("  Difference: %d bytes", totalActualSize-geometryPrediction)

		require.Equal(t, geometryPrediction, totalActualSize, "Geometry prediction should match actual total size")
	})

	t.Run("DebugGeometryCalculation", func(t *testing.T) {
		// Debug the exact geometry calculation step by step
		nikeScheme := schemes.ByName("x25519")
		require.NotNil(t, nikeScheme)

		g := pigeonholegeo.NewGeometry(4559, nikeScheme)

		// Manually calculate what the geometry should be
		// Step 1: BACAP payload (MaxPlaintextPayloadLength + length prefix + BACAP overhead)
		bacapPayloadSize := g.MaxPlaintextPayloadLength + 4 + 16 // length prefix + bacapEncryptionOverhead
		t.Logf("Step 1 - BACAP payload: %d + 4 + 16 = %d", g.MaxPlaintextPayloadLength, bacapPayloadSize)

		// Step 2: ReplicaWrite
		replicaWriteOverhead := 32 + 64 + 4 // BoxID + Signature + PayloadLen
		replicaWriteSize := replicaWriteOverhead + bacapPayloadSize
		t.Logf("Step 2 - ReplicaWrite: %d + %d = %d", replicaWriteOverhead, bacapPayloadSize, replicaWriteSize)

		// Step 3: ReplicaInnerMessage
		replicaInnerMessageSize := 1 + replicaWriteSize // MessageType + ReplicaWrite
		t.Logf("Step 3 - ReplicaInnerMessage: 1 + %d = %d", replicaWriteSize, replicaInnerMessageSize)

		// Step 4: MKEM ciphertext
		mkemCiphertextSize := replicaInnerMessageSize + 28 // mkemEncryptionOverhead
		t.Logf("Step 4 - MKEM ciphertext: %d + 28 = %d", replicaInnerMessageSize, mkemCiphertextSize)

		// Step 5: CourierEnvelope
		senderPubkeySize := nikeScheme.PublicKeySize()
		courierEnvelopeFixedOverhead := 2 + 60 + 60 + 1 + 8 + 2 + 4 // All fixed fields
		courierEnvelopeOverhead := courierEnvelopeFixedOverhead + senderPubkeySize
		courierEnvelopeSize := courierEnvelopeOverhead + mkemCiphertextSize
		t.Logf("Step 5 - CourierEnvelope: (%d + %d) + %d = %d", courierEnvelopeFixedOverhead, senderPubkeySize, mkemCiphertextSize, courierEnvelopeSize)

		// Step 6: CourierQuery
		courierQueryOverhead := 1 // QueryType (union discriminator, no envelope length prefix in trunnel)
		courierQuerySize := courierEnvelopeSize + courierQueryOverhead
		t.Logf("Step 6 - CourierQuery: %d + %d = %d", courierEnvelopeSize, courierQueryOverhead, courierQuerySize)

		// Compare with geometry calculation
		geometryPrediction := g.CourierQueryWriteLength
		t.Logf("Manual calculation: %d", courierQuerySize)
		t.Logf("Geometry prediction: %d", geometryPrediction)
		t.Logf("Difference: %d", geometryPrediction-courierQuerySize)

		require.Equal(t, courierQuerySize, geometryPrediction, "Manual calculation should match geometry prediction")
	})

	t.Run("IntegrationTestGeometry", func(t *testing.T) {
		// Test the exact geometry used in the integration test
		nikeScheme := schemes.ByName("CTIDH1024-X25519")
		require.NotNil(t, nikeScheme)

		g := pigeonholegeo.NewGeometry(4551, nikeScheme) // BoxPayloadLength from integration test

		t.Logf("Integration test geometry:")
		t.Logf("  MaxPlaintextPayloadLength: %d", g.MaxPlaintextPayloadLength)
		t.Logf("  CourierQueryWriteLength: %d", g.CourierQueryWriteLength)
		t.Logf("  CourierQueryReadLength: %d", g.CourierQueryReadLength)

		// The integration test expects CourierQueryWriteLength to be 5000
		// but our corrected calculation gives a different value
		expectedFromSphinx := 5000
		actualCalculated := g.CourierQueryWriteLength

		t.Logf("Expected from Sphinx constraint: %d", expectedFromSphinx)
		t.Logf("Actual calculated: %d", actualCalculated)
		t.Logf("Difference: %d", actualCalculated-expectedFromSphinx)

		// This test will show us the discrepancy
		if actualCalculated != expectedFromSphinx {
			t.Logf("DISCREPANCY: Integration test expects %d but geometry calculates %d",
				expectedFromSphinx, actualCalculated)
		}
	})
}

func TestGeometryCourierEnvelopeCiphertextSizeHelpers(t *testing.T) {
	// Test the new exported helper methods for calculating courier envelope ciphertext sizes
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	maxPlaintextPayloadLength := 1000
	g := pigeonholegeo.NewGeometry(maxPlaintextPayloadLength, nikeScheme)
	require.NoError(t, g.Validate())

	t.Run("ReadCiphertextSize", func(t *testing.T) {
		// Test CalculateCourierEnvelopeCiphertextSizeRead
		readCiphertextSize := g.CalculateCourierEnvelopeCiphertextSizeRead()

		// Verify it matches the calculation from calculateCourierQueryReadLength
		// BoxID + MessageType + MKEM overhead
		expectedReadSize := bacap.BoxIDSize + 1 + 28 // BoxID + MessageType + MKEM overhead
		require.Equal(t, expectedReadSize, readCiphertextSize)

		t.Logf("Read ciphertext size: %d bytes", readCiphertextSize)
		t.Logf("  BoxID: %d bytes", bacap.BoxIDSize)
		t.Logf("  MessageType: 1 byte")
		t.Logf("  MKEM overhead: 28 bytes")
	})

	t.Run("WriteCiphertextSize", func(t *testing.T) {
		// Test CalculateCourierEnvelopeCiphertextSizeWrite
		writeCiphertextSize := g.CalculateCourierEnvelopeCiphertextSizeWrite()

		// Verify it matches the calculation from calculateCourierQueryWriteLength
		// BACAP ciphertext = MaxPlaintextPayloadLength + lengthPrefix + bacapOverhead
		bacapCiphertextSize := g.CalculateBoxCiphertextLength()
		expectedWriteSize := 1 + 100 + bacapCiphertextSize + 28 // MessageType + ReplicaWriteFixedOverhead + BACAP ciphertext + MKEM overhead
		require.Equal(t, expectedWriteSize, writeCiphertextSize)

		t.Logf("Write ciphertext size: %d bytes", writeCiphertextSize)
		t.Logf("  MessageType: 1 byte")
		t.Logf("  ReplicaWrite fixed overhead: 100 bytes")
		t.Logf("  BACAP ciphertext: %d bytes", bacapCiphertextSize)
		t.Logf("    MaxPlaintextPayloadLength: %d bytes", g.MaxPlaintextPayloadLength)
		t.Logf("    Length prefix: 4 bytes")
		t.Logf("    BACAP encryption overhead: 16 bytes")
		t.Logf("  MKEM overhead: 28 bytes")
	})

	t.Run("CompareWithActualGeometry", func(t *testing.T) {
		// Verify the helper methods produce sizes that are consistent with the geometry calculations
		readCiphertextSize := g.CalculateCourierEnvelopeCiphertextSizeRead()
		writeCiphertextSize := g.CalculateCourierEnvelopeCiphertextSizeWrite()

		// The ciphertext sizes should be reasonable compared to the overall query sizes
		require.Greater(t, g.CourierQueryReadLength, readCiphertextSize)
		require.Greater(t, g.CourierQueryWriteLength, writeCiphertextSize)

		t.Logf("CourierQueryReadLength: %d bytes (includes %d bytes ciphertext)",
			g.CourierQueryReadLength, readCiphertextSize)
		t.Logf("CourierQueryWriteLength: %d bytes (includes %d bytes ciphertext)",
			g.CourierQueryWriteLength, writeCiphertextSize)

		// Write ciphertext should be much larger than read ciphertext
		require.Greater(t, writeCiphertextSize, readCiphertextSize)
	})
}

func TestCourierEnvelopeCiphertextSizePredictions(t *testing.T) {
	// Test that the new helper methods give accurate predictions by creating real messages
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	maxPlaintextPayloadLength := 500
	g := pigeonholegeo.NewGeometry(maxPlaintextPayloadLength, nikeScheme)
	require.NoError(t, g.Validate())

	// Create BACAP keys for testing
	aliceOwner, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	aliceStatefulWriter, err := bacap.NewStatefulWriter(aliceOwner, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)

	// Create MKEM keys for replicas
	mkemNikeScheme := mkem.NewScheme(nikeScheme)
	replicaPublicKey1, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	replicaPublicKey2, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	replicaPubKeys := []nike.PublicKey{replicaPublicKey1, replicaPublicKey2}

	t.Run("ReadCiphertextSizePrediction", func(t *testing.T) {
		// Test read query ciphertext size prediction
		predictedSize := g.CalculateCourierEnvelopeCiphertextSizeRead()

		// Create a real read query
		boxID := [bacap.BoxIDSize]byte{}
		_, err := rand.Read(boxID[:])
		require.NoError(t, err)

		// Create ReplicaRead
		readRequest := pigeonhole.ReplicaRead{
			BoxID: boxID,
		}

		// Create ReplicaInnerMessage
		msg := &pigeonhole.ReplicaInnerMessage{
			MessageType: 0, // 0 = read
			ReadMsg:     &readRequest,
		}

		// MKEM encrypt the inner message
		_, mkemCiphertext := mkemNikeScheme.Encapsulate(replicaPubKeys, msg.Bytes())

		// Measure the actual ciphertext size
		actualSize := len(mkemCiphertext.Envelope)

		t.Logf("Read ciphertext prediction: %d bytes", predictedSize)
		t.Logf("Actual read ciphertext size: %d bytes", actualSize)
		t.Logf("Difference: %d bytes", actualSize-predictedSize)

		// The prediction should match exactly
		require.Equal(t, predictedSize, actualSize,
			"Read ciphertext size prediction should be exact")
	})

	t.Run("WriteCiphertextSizePrediction", func(t *testing.T) {
		// Test write query ciphertext size prediction
		predictedSize := g.CalculateCourierEnvelopeCiphertextSizeWrite()

		// Create test message that uses the full capacity
		testMessage := make([]byte, g.MaxPlaintextPayloadLength)
		for i := range testMessage {
			testMessage[i] = byte(i % 256)
		}

		// Create padded payload with length prefix for BACAP
		paddedPayload, err := pigeonhole.CreatePaddedPayload(testMessage, g.MaxPlaintextPayloadLength+4)
		require.NoError(t, err)

		// BACAP encrypt the padded payload
		boxID, ciphertext, sigraw, err := aliceStatefulWriter.EncryptNext(paddedPayload)
		require.NoError(t, err)

		sig := [bacap.SignatureSize]byte{}
		copy(sig[:], sigraw)

		// Create ReplicaWrite
		writeRequest := pigeonhole.ReplicaWrite{
			BoxID:      boxID,
			Signature:  sig,
			PayloadLen: uint32(len(ciphertext)),
			Payload:    ciphertext,
		}

		// Create ReplicaInnerMessage
		msg := &pigeonhole.ReplicaInnerMessage{
			MessageType: 1, // 1 = write
			WriteMsg:    &writeRequest,
		}

		// MKEM encrypt the inner message
		_, mkemCiphertext := mkemNikeScheme.Encapsulate(replicaPubKeys, msg.Bytes())

		// Measure the actual ciphertext size
		actualSize := len(mkemCiphertext.Envelope)

		t.Logf("Write ciphertext prediction: %d bytes", predictedSize)
		t.Logf("Actual write ciphertext size: %d bytes", actualSize)
		t.Logf("Difference: %d bytes", actualSize-predictedSize)

		// The prediction should match exactly
		require.Equal(t, predictedSize, actualSize,
			"Write ciphertext size prediction should be exact")
	})

	t.Run("VariousPayloadSizes", func(t *testing.T) {
		// Test predictions with different payload sizes
		testSizes := []int{100, 250, 500, 1000, 2000}

		for _, size := range testSizes {
			t.Run(fmt.Sprintf("PayloadSize_%d", size), func(t *testing.T) {
				testGeometry := pigeonholegeo.NewGeometry(size, nikeScheme)
				require.NoError(t, testGeometry.Validate())

				// Test read prediction
				readPrediction := testGeometry.CalculateCourierEnvelopeCiphertextSizeRead()

				// Create minimal read message
				boxID := [bacap.BoxIDSize]byte{}
				readRequest := pigeonhole.ReplicaRead{BoxID: boxID}
				readMsg := &pigeonhole.ReplicaInnerMessage{
					MessageType: 0,
					ReadMsg:     &readRequest,
				}
				_, readCiphertext := mkemNikeScheme.Encapsulate(replicaPubKeys, readMsg.Bytes())
				actualReadSize := len(readCiphertext.Envelope)

				require.Equal(t, readPrediction, actualReadSize,
					"Read prediction failed for payload size %d", size)

				// Test write prediction
				writePrediction := testGeometry.CalculateCourierEnvelopeCiphertextSizeWrite()

				// Create write message with actual payload
				testPayload := make([]byte, size)
				paddedPayload, err := pigeonhole.CreatePaddedPayload(testPayload, size+4)
				require.NoError(t, err)

				boxID, ciphertext, sigraw, err := aliceStatefulWriter.EncryptNext(paddedPayload)
				require.NoError(t, err)

				sig := [bacap.SignatureSize]byte{}
				copy(sig[:], sigraw)

				writeRequest := pigeonhole.ReplicaWrite{
					BoxID:      boxID,
					Signature:  sig,
					PayloadLen: uint32(len(ciphertext)),
					Payload:    ciphertext,
				}
				writeMsg := &pigeonhole.ReplicaInnerMessage{
					MessageType: 1,
					WriteMsg:    &writeRequest,
				}
				_, writeCiphertext := mkemNikeScheme.Encapsulate(replicaPubKeys, writeMsg.Bytes())
				actualWriteSize := len(writeCiphertext.Envelope)

				require.Equal(t, writePrediction, actualWriteSize,
					"Write prediction failed for payload size %d", size)

				t.Logf("Size %d: Read %d bytes, Write %d bytes",
					size, actualReadSize, actualWriteSize)
			})
		}
	})
}

func TestEnvelopeReplySizePredictions(t *testing.T) {
	// Test that the new EnvelopeReply helper methods give accurate predictions
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	maxPlaintextPayloadLength := 500
	g := pigeonholegeo.NewGeometry(maxPlaintextPayloadLength, nikeScheme)
	require.NoError(t, g.Validate())

	// Create BACAP keys for testing
	aliceOwner, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	aliceStatefulWriter, err := bacap.NewStatefulWriter(aliceOwner, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)

	// Create MKEM scheme and keys for EnvelopeReply
	mkemNikeScheme := mkem.NewScheme(nikeScheme)
	_, replicaPrivateKey, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	senderPublicKey, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)

	t.Run("ReadEnvelopeReplySizePrediction", func(t *testing.T) {
		// Test read reply EnvelopeReply size prediction
		predictedSize := g.CalculateEnvelopeReplySizeRead()

		// Create test message that uses the full capacity
		testMessage := make([]byte, g.MaxPlaintextPayloadLength)
		for i := range testMessage {
			testMessage[i] = byte(i % 256)
		}

		// Create padded payload and BACAP encrypt it
		paddedPayload, err := pigeonhole.CreatePaddedPayload(testMessage, g.MaxPlaintextPayloadLength+4)
		require.NoError(t, err)

		boxID, ciphertext, sigraw, err := aliceStatefulWriter.EncryptNext(paddedPayload)
		require.NoError(t, err)

		sig := [bacap.SignatureSize]byte{}
		copy(sig[:], sigraw)

		// Create ReplicaReadReply
		readReply := &pigeonhole.ReplicaReadReply{
			ErrorCode:  0, // success
			BoxID:      boxID,
			Signature:  sig,
			PayloadLen: uint32(len(ciphertext)),
			Payload:    ciphertext,
		}

		// Create ReplicaMessageReplyInnerMessage
		replyInnerMessage := &pigeonhole.ReplicaMessageReplyInnerMessage{
			MessageType: 0, // 0 = read_reply
			ReadReply:   readReply,
		}

		// Create EnvelopeReply using MKEM scheme
		replyInnerMessageBlob := replyInnerMessage.Bytes()
		envelopeReply := mkemNikeScheme.EnvelopeReply(replicaPrivateKey, senderPublicKey, replyInnerMessageBlob)

		// Measure the actual EnvelopeReply size
		actualSize := len(envelopeReply.Envelope)

		t.Logf("Read EnvelopeReply prediction: %d bytes", predictedSize)
		t.Logf("Actual read EnvelopeReply size: %d bytes", actualSize)
		t.Logf("Difference: %d bytes", actualSize-predictedSize)

		// The prediction should match exactly
		require.Equal(t, predictedSize, actualSize,
			"Read EnvelopeReply size prediction should be exact")
	})

	t.Run("WriteEnvelopeReplySizePrediction", func(t *testing.T) {
		// Test write reply EnvelopeReply size prediction
		predictedSize := g.CalculateEnvelopeReplySizeWrite()

		// Create ReplicaWriteReply (just an error code)
		writeReply := &pigeonhole.ReplicaWriteReply{
			ErrorCode: 0, // success
		}

		// Create ReplicaMessageReplyInnerMessage
		replyInnerMessage := &pigeonhole.ReplicaMessageReplyInnerMessage{
			MessageType: 1, // 1 = write_reply
			WriteReply:  writeReply,
		}

		// Create EnvelopeReply using MKEM scheme
		replyInnerMessageBlob := replyInnerMessage.Bytes()
		envelopeReply := mkemNikeScheme.EnvelopeReply(replicaPrivateKey, senderPublicKey, replyInnerMessageBlob)

		// Measure the actual EnvelopeReply size
		actualSize := len(envelopeReply.Envelope)

		t.Logf("Write EnvelopeReply prediction: %d bytes", predictedSize)
		t.Logf("Actual write EnvelopeReply size: %d bytes", actualSize)
		t.Logf("Difference: %d bytes", actualSize-predictedSize)

		// The prediction should match exactly
		require.Equal(t, predictedSize, actualSize,
			"Write EnvelopeReply size prediction should be exact")
	})

	t.Run("VariousPayloadSizesEnvelopeReply", func(t *testing.T) {
		// Test predictions with different payload sizes
		testSizes := []int{100, 250, 500, 1000}

		for _, size := range testSizes {
			t.Run(fmt.Sprintf("PayloadSize_%d", size), func(t *testing.T) {
				testGeometry := pigeonholegeo.NewGeometry(size, nikeScheme)
				require.NoError(t, testGeometry.Validate())

				// Test read EnvelopeReply prediction
				readPrediction := testGeometry.CalculateEnvelopeReplySizeRead()

				// Create read reply with actual payload
				testPayload := make([]byte, size)
				paddedPayload, err := pigeonhole.CreatePaddedPayload(testPayload, size+4)
				require.NoError(t, err)

				boxID, ciphertext, sigraw, err := aliceStatefulWriter.EncryptNext(paddedPayload)
				require.NoError(t, err)

				sig := [bacap.SignatureSize]byte{}
				copy(sig[:], sigraw)

				readReply := &pigeonhole.ReplicaReadReply{
					ErrorCode:  0,
					BoxID:      boxID,
					Signature:  sig,
					PayloadLen: uint32(len(ciphertext)),
					Payload:    ciphertext,
				}
				replyInnerMessage := &pigeonhole.ReplicaMessageReplyInnerMessage{
					MessageType: 0,
					ReadReply:   readReply,
				}
				envelopeReply := mkemNikeScheme.EnvelopeReply(replicaPrivateKey, senderPublicKey, replyInnerMessage.Bytes())
				actualReadSize := len(envelopeReply.Envelope)

				require.Equal(t, readPrediction, actualReadSize,
					"Read EnvelopeReply prediction failed for payload size %d", size)

				// Test write EnvelopeReply prediction
				writePrediction := testGeometry.CalculateEnvelopeReplySizeWrite()

				writeReply := &pigeonhole.ReplicaWriteReply{ErrorCode: 0}
				writeReplyInnerMessage := &pigeonhole.ReplicaMessageReplyInnerMessage{
					MessageType: 1,
					WriteReply:  writeReply,
				}
				writeEnvelopeReply := mkemNikeScheme.EnvelopeReply(replicaPrivateKey, senderPublicKey, writeReplyInnerMessage.Bytes())
				actualWriteSize := len(writeEnvelopeReply.Envelope)

				require.Equal(t, writePrediction, actualWriteSize,
					"Write EnvelopeReply prediction failed for payload size %d", size)

				t.Logf("Size %d: Read EnvelopeReply %d bytes, Write EnvelopeReply %d bytes",
					size, actualReadSize, actualWriteSize)
			})
		}
	})
}

func TestGeometryLengthPrefixBug(t *testing.T) {
	// TDD test to expose the bug: geometry predictions don't account for 4-byte length prefix overhead
	// This test should FAIL initially, showing the geometry prediction is wrong
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	// Use a small BoxPayloadLength to make the bug more obvious
	boxPayloadLength := 100
	g := pigeonholegeo.NewGeometry(boxPayloadLength, nikeScheme)
	require.NoError(t, g.Validate())

	// Create BACAP keys
	aliceOwner, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	aliceStatefulWriter, err := bacap.NewStatefulWriter(aliceOwner, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)

	// Create MKEM keys for replicas
	mkemNikeScheme := mkem.NewScheme(nikeScheme)
	replicaPublicKey1, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	replicaPublicKey2, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	replicaPubKeys := []nike.PublicKey{replicaPublicKey1, replicaPublicKey2}

	// The key insight: MaxPlaintextPayloadLength should represent the maximum usable plaintext size
	// But CreatePaddedPayload creates a payload that includes the 4-byte length prefix
	// So the actual BACAP input is MaxPlaintextPayloadLength + 4 bytes, but it contains:
	// - 4 bytes length prefix + actual message data + padding

	// Let's create a message that uses the FULL MaxPlaintextPayloadLength capacity
	// This means: message + 4-byte length prefix = MaxPlaintextPayloadLength + 4
	maxMessageSize := g.MaxPlaintextPayloadLength // Use the full capacity
	fullMessage := make([]byte, maxMessageSize)
	for i := range fullMessage {
		fullMessage[i] = byte(i % 256) // Fill with test data
	}

	// Create padded payload - this should be exactly MaxPlaintextPayloadLength + 4 bytes
	paddedPayload, err := pigeonhole.CreatePaddedPayload(fullMessage, g.MaxPlaintextPayloadLength+4)
	require.NoError(t, err)

	t.Logf("Full message size: %d bytes", len(fullMessage))
	t.Logf("MaxPlaintextPayloadLength: %d bytes", g.MaxPlaintextPayloadLength)
	t.Logf("Padded payload size: %d bytes", len(paddedPayload))
	t.Logf("Expected: padded payload should equal MaxPlaintextPayloadLength + 4")

	// Verify that the padded payload is exactly MaxPlaintextPayloadLength + 4
	require.Equal(t, g.MaxPlaintextPayloadLength+4, len(paddedPayload),
		"CreatePaddedPayload should create payload of exactly MaxPlaintextPayloadLength + 4 bytes")

	// BACAP encrypt the padded payload
	boxID, ciphertext, sigraw, err := aliceStatefulWriter.EncryptNext(paddedPayload)
	require.NoError(t, err)

	sig := [bacap.SignatureSize]byte{}
	copy(sig[:], sigraw)

	// Create ReplicaWrite
	writeRequest := pigeonhole.ReplicaWrite{
		BoxID:      boxID,
		Signature:  sig,
		PayloadLen: uint32(len(ciphertext)),
		Payload:    ciphertext,
	}

	// Create ReplicaInnerMessage
	msg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 1, // 1 = write
		WriteMsg:    &writeRequest,
	}

	// MKEM encrypt the inner message
	mkemPrivateKey, mkemCiphertext := mkemNikeScheme.Encapsulate(replicaPubKeys, msg.Bytes())
	mkemPublicKey := mkemPrivateKey.Public()
	senderPubkeyBytes := mkemPublicKey.Bytes()

	// Create CourierEnvelope
	envelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1},
		Dek1:                 *mkemCiphertext.DEKCiphertexts[0],
		Dek2:                 *mkemCiphertext.DEKCiphertexts[1],
		ReplyIndex:           0,
		Epoch:                1,
		SenderPubkeyLen:      uint16(len(senderPubkeyBytes)),
		SenderPubkey:         senderPubkeyBytes,
		CiphertextLen:        uint32(len(mkemCiphertext.Envelope)),
		Ciphertext:           mkemCiphertext.Envelope,
	}

	// Create CourierQuery
	query := &pigeonhole.CourierQuery{
		QueryType: 0, // 0 = envelope
		Envelope:  envelope,
	}

	// Test the actual serialized size against geometry prediction
	serialized := query.Bytes()
	actualSize := len(serialized)
	predictedSize := g.CourierQueryWriteLength

	t.Logf("Predicted CourierQueryWriteLength: %d bytes", predictedSize)
	t.Logf("Actual serialized size: %d bytes", actualSize)
	t.Logf("Difference: %d bytes", actualSize-predictedSize)

	// This test should FAIL initially because the geometry doesn't account for the 4-byte length prefix
	// The actual size should be 4 bytes larger than predicted due to the length prefix overhead
	require.Equal(t, predictedSize, actualSize,
		"Geometry prediction should match actual size (this test should fail initially, exposing the length prefix bug)")
}

func TestCalculateEnvelopeReplySizeRead(t *testing.T) {
	// Test the CalculateEnvelopeReplySizeRead function by creating real EnvelopeReply messages
	// and comparing their actual sizes with the geometry predictions
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	// Test with different payload sizes to ensure the function works correctly across various scenarios
	testSizes := []int{100, 500, 1000, 2000}

	for _, maxPlaintextPayloadLength := range testSizes {
		t.Run(fmt.Sprintf("PayloadSize_%d", maxPlaintextPayloadLength), func(t *testing.T) {
			g := pigeonholegeo.NewGeometry(maxPlaintextPayloadLength, nikeScheme)
			require.NoError(t, g.Validate())

			// Create BACAP keys for testing
			aliceOwner, err := bacap.NewWriteCap(rand.Reader)
			require.NoError(t, err)
			aliceStatefulWriter, err := bacap.NewStatefulWriter(aliceOwner, constants.PIGEONHOLE_CTX)
			require.NoError(t, err)

			// Create MKEM scheme and keys for EnvelopeReply
			mkemNikeScheme := mkem.NewScheme(nikeScheme)
			_, replicaPrivateKey, err := nikeScheme.GenerateKeyPair()
			require.NoError(t, err)
			senderPublicKey, _, err := nikeScheme.GenerateKeyPair()
			require.NoError(t, err)

			// Get the prediction from the function we're testing
			predictedSize := g.CalculateEnvelopeReplySizeRead()

			// Create test message that uses the full capacity
			testMessage := make([]byte, g.MaxPlaintextPayloadLength)
			for i := range testMessage {
				testMessage[i] = byte(i % 256)
			}

			// Create padded payload and BACAP encrypt it
			paddedPayload, err := pigeonhole.CreatePaddedPayload(testMessage, g.MaxPlaintextPayloadLength+4)
			require.NoError(t, err)

			boxID, ciphertext, sigraw, err := aliceStatefulWriter.EncryptNext(paddedPayload)
			require.NoError(t, err)

			sig := [bacap.SignatureSize]byte{}
			copy(sig[:], sigraw)

			// Create ReplicaReadReply
			readReply := &pigeonhole.ReplicaReadReply{
				ErrorCode:  0, // success
				BoxID:      boxID,
				Signature:  sig,
				PayloadLen: uint32(len(ciphertext)),
				Payload:    ciphertext,
			}

			// Create ReplicaMessageReplyInnerMessage
			replyInnerMessage := &pigeonhole.ReplicaMessageReplyInnerMessage{
				MessageType: 0, // 0 = read_reply
				ReadReply:   readReply,
			}

			// Create EnvelopeReply using MKEM scheme
			replyInnerMessageBlob := replyInnerMessage.Bytes()
			envelopeReply := mkemNikeScheme.EnvelopeReply(replicaPrivateKey, senderPublicKey, replyInnerMessageBlob)

			// Measure the actual EnvelopeReply size
			actualSize := len(envelopeReply.Envelope)

			t.Logf("MaxPlaintextPayloadLength: %d bytes", g.MaxPlaintextPayloadLength)
			t.Logf("Test message size: %d bytes", len(testMessage))
			t.Logf("Padded payload size: %d bytes", len(paddedPayload))
			t.Logf("BACAP ciphertext size: %d bytes", len(ciphertext))
			t.Logf("ReplicaReadReply size: %d bytes", len(readReply.Bytes()))
			t.Logf("ReplicaMessageReplyInnerMessage size: %d bytes", len(replyInnerMessageBlob))
			t.Logf("Predicted EnvelopeReply size: %d bytes", predictedSize)
			t.Logf("Actual EnvelopeReply size: %d bytes", actualSize)
			t.Logf("Difference: %d bytes", actualSize-predictedSize)

			// The prediction should match exactly
			require.Equal(t, predictedSize, actualSize,
				"CalculateEnvelopeReplySizeRead prediction should be exact for payload size %d", maxPlaintextPayloadLength)
		})
	}
}

func TestCalculateEnvelopeReplySizeReadDetailed(t *testing.T) {
	// Detailed test that validates the internal calculation steps of CalculateEnvelopeReplySizeRead
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	maxPlaintextPayloadLength := 500
	g := pigeonholegeo.NewGeometry(maxPlaintextPayloadLength, nikeScheme)
	require.NoError(t, g.Validate())

	// Create BACAP keys for testing
	aliceOwner, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	aliceStatefulWriter, err := bacap.NewStatefulWriter(aliceOwner, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)

	// Create MKEM scheme and keys for EnvelopeReply
	mkemNikeScheme := mkem.NewScheme(nikeScheme)
	_, replicaPrivateKey, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	senderPublicKey, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)

	t.Run("StepByStepCalculation", func(t *testing.T) {
		// Manually calculate what CalculateEnvelopeReplySizeRead should return
		// and verify each step matches the actual implementation

		// Step 1: BACAP ciphertext size
		bacapCiphertextSize := g.CalculateBoxCiphertextLength()
		expectedBACAPSize := g.MaxPlaintextPayloadLength + 4 + 16 // lengthPrefix + bacapOverhead
		require.Equal(t, expectedBACAPSize, bacapCiphertextSize)
		t.Logf("Step 1 - BACAP ciphertext: %d bytes", bacapCiphertextSize)

		// Step 2: ReplicaReadReply size
		// ErrorCode (1) + BoxID (32) + Signature (64) + PayloadLen (4) + Payload
		expectedReplicaReadReplySize := 1 + bacap.BoxIDSize + bacap.SignatureSize + 4 + bacapCiphertextSize
		t.Logf("Step 2 - ReplicaReadReply: 1 + %d + %d + 4 + %d = %d bytes",
			bacap.BoxIDSize, bacap.SignatureSize, bacapCiphertextSize, expectedReplicaReadReplySize)

		// Step 3: ReplicaMessageReplyInnerMessage size
		// MessageType (1) + ReplicaReadReply
		expectedReplicaMessageReplyInnerSize := 1 + expectedReplicaReadReplySize
		t.Logf("Step 3 - ReplicaMessageReplyInnerMessage: 1 + %d = %d bytes",
			expectedReplicaReadReplySize, expectedReplicaMessageReplyInnerSize)

		// Step 4: EnvelopeReply encryption overhead
		// ChaCha20Poly1305: 12-byte nonce + 16-byte auth tag
		envelopeReplyOverhead := 12 + 16
		expectedEnvelopeReplySize := expectedReplicaMessageReplyInnerSize + envelopeReplyOverhead
		t.Logf("Step 4 - EnvelopeReply: %d + %d = %d bytes",
			expectedReplicaMessageReplyInnerSize, envelopeReplyOverhead, expectedEnvelopeReplySize)

		// Compare with the function's calculation
		actualPrediction := g.CalculateEnvelopeReplySizeRead()
		t.Logf("Function prediction: %d bytes", actualPrediction)
		t.Logf("Manual calculation: %d bytes", expectedEnvelopeReplySize)

		require.Equal(t, expectedEnvelopeReplySize, actualPrediction,
			"Manual calculation should match function prediction")
	})

	t.Run("ActualMessageValidation", func(t *testing.T) {
		// Create a real message and validate the prediction
		testMessage := make([]byte, g.MaxPlaintextPayloadLength)
		for i := range testMessage {
			testMessage[i] = byte(i % 256)
		}

		// Create padded payload and BACAP encrypt it
		paddedPayload, err := pigeonhole.CreatePaddedPayload(testMessage, g.MaxPlaintextPayloadLength+4)
		require.NoError(t, err)

		boxID, ciphertext, sigraw, err := aliceStatefulWriter.EncryptNext(paddedPayload)
		require.NoError(t, err)

		sig := [bacap.SignatureSize]byte{}
		copy(sig[:], sigraw)

		// Create ReplicaReadReply
		readReply := &pigeonhole.ReplicaReadReply{
			ErrorCode:  0, // success
			BoxID:      boxID,
			Signature:  sig,
			PayloadLen: uint32(len(ciphertext)),
			Payload:    ciphertext,
		}

		// Verify ReplicaReadReply size matches our calculation
		replicaReadReplyBytes := readReply.Bytes()
		expectedReplicaReadReplySize := 1 + bacap.BoxIDSize + bacap.SignatureSize + 4 + len(ciphertext)
		require.Equal(t, expectedReplicaReadReplySize, len(replicaReadReplyBytes),
			"ReplicaReadReply size should match calculation")

		// Create ReplicaMessageReplyInnerMessage
		replyInnerMessage := &pigeonhole.ReplicaMessageReplyInnerMessage{
			MessageType: 0, // 0 = read_reply
			ReadReply:   readReply,
		}

		// Verify ReplicaMessageReplyInnerMessage size
		replyInnerMessageBytes := replyInnerMessage.Bytes()
		expectedReplyInnerSize := 1 + len(replicaReadReplyBytes)
		require.Equal(t, expectedReplyInnerSize, len(replyInnerMessageBytes),
			"ReplicaMessageReplyInnerMessage size should match calculation")

		// Create EnvelopeReply using MKEM scheme
		envelopeReply := mkemNikeScheme.EnvelopeReply(replicaPrivateKey, senderPublicKey, replyInnerMessageBytes)

		// Verify the final EnvelopeReply size
		actualSize := len(envelopeReply.Envelope)
		predictedSize := g.CalculateEnvelopeReplySizeRead()

		t.Logf("ReplicaReadReply size: %d bytes", len(replicaReadReplyBytes))
		t.Logf("ReplicaMessageReplyInnerMessage size: %d bytes", len(replyInnerMessageBytes))
		t.Logf("EnvelopeReply predicted size: %d bytes", predictedSize)
		t.Logf("EnvelopeReply actual size: %d bytes", actualSize)

		require.Equal(t, predictedSize, actualSize,
			"EnvelopeReply size prediction should be exact")
	})

	t.Run("ErrorCaseHandling", func(t *testing.T) {
		// Test with an error reply to ensure the function works for different scenarios
		// Create ReplicaReadReply with error
		errorReply := &pigeonhole.ReplicaReadReply{
			ErrorCode:  1,                           // error
			BoxID:      [bacap.BoxIDSize]byte{},     // empty BoxID for error case
			Signature:  [bacap.SignatureSize]byte{}, // empty signature for error case
			PayloadLen: 0,                           // no payload for error case
			Payload:    nil,
		}

		// Create ReplicaMessageReplyInnerMessage
		errorReplyInnerMessage := &pigeonhole.ReplicaMessageReplyInnerMessage{
			MessageType: 0, // 0 = read_reply
			ReadReply:   errorReply,
		}

		// Create EnvelopeReply
		errorReplyInnerMessageBytes := errorReplyInnerMessage.Bytes()
		errorEnvelopeReply := mkemNikeScheme.EnvelopeReply(replicaPrivateKey, senderPublicKey, errorReplyInnerMessageBytes)

		// The prediction should still be based on the maximum possible size (success case)
		// because the geometry function calculates for the worst-case scenario
		predictedSize := g.CalculateEnvelopeReplySizeRead()
		actualErrorSize := len(errorEnvelopeReply.Envelope)

		t.Logf("Error reply size: %d bytes", actualErrorSize)
		t.Logf("Predicted size (success case): %d bytes", predictedSize)

		// The error case should be smaller than the predicted size
		require.Less(t, actualErrorSize, predictedSize,
			"Error reply should be smaller than the predicted maximum size")
	})
}

func TestMaxCourierEnvelopePlaintext(t *testing.T) {
	// Test that MaxCourierEnvelopePlaintext correctly calculates the maximum
	// plaintext size such that the resulting CourierEnvelope fits in a Box
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	boxPayloadLength := 1000
	g := pigeonholegeo.NewGeometry(boxPayloadLength, nikeScheme)
	require.NoError(t, g.Validate())

	// Get the maximum plaintext size for a CourierEnvelope
	maxPlaintext := g.MaxCourierEnvelopePlaintext()
	require.Greater(t, maxPlaintext, 0, "MaxCourierEnvelopePlaintext should be positive")
	require.Less(t, maxPlaintext, boxPayloadLength, "MaxCourierEnvelopePlaintext should be less than box payload")

	t.Logf("Box payload length: %d bytes", boxPayloadLength)
	t.Logf("Max CourierEnvelope plaintext: %d bytes", maxPlaintext)
	t.Logf("Overhead: %d bytes", boxPayloadLength-maxPlaintext)

	// Create a test CourierEnvelope with the maximum plaintext size
	// and verify it fits in a Box
	plaintext := make([]byte, maxPlaintext)
	_, err := rand.Reader.Read(plaintext)
	require.NoError(t, err)

	// Create BACAP writer for destination
	destWriteCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	destWriter, err := bacap.NewStatefulWriter(destWriteCap, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)

	// Encrypt plaintext with BACAP
	boxID, bacapCiphertext, sigRaw, err := destWriter.EncryptNext(plaintext)
	require.NoError(t, err)

	// Convert signature to fixed-size array
	var sig [64]uint8
	copy(sig[:], sigRaw)

	// Create ReplicaWrite
	replicaWrite := &pigeonhole.ReplicaWrite{
		BoxID:      boxID,
		Signature:  sig,
		PayloadLen: uint32(len(bacapCiphertext)),
		Payload:    bacapCiphertext,
	}

	// Wrap in ReplicaInnerMessage
	replicaInnerMsg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 1, // Write
		WriteMsg:    replicaWrite,
	}
	replicaInnerBytes, err := replicaInnerMsg.MarshalBinary()
	require.NoError(t, err)

	// Encrypt with MKEM
	mkemScheme := mkem.NewScheme(nikeScheme)

	// Generate replica keys
	replica1Pub, _, err := mkemScheme.GenerateKeyPair()
	require.NoError(t, err)
	replica2Pub, _, err := mkemScheme.GenerateKeyPair()
	require.NoError(t, err)

	replicaKeys := []nike.PublicKey{replica1Pub, replica2Pub}
	ephPriv, mkemCiphertext := mkemScheme.Encapsulate(replicaKeys, replicaInnerBytes)

	// Create CourierEnvelope
	courierEnvelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1},
		Dek1:                 *mkemCiphertext.DEKCiphertexts[0],
		Dek2:                 *mkemCiphertext.DEKCiphertexts[1],
		ReplyIndex:           0,
		Epoch:                0,
		SenderPubkeyLen:      uint16(len(ephPriv.Public().Bytes())),
		SenderPubkey:         ephPriv.Public().Bytes(),
		CiphertextLen:        uint32(len(mkemCiphertext.Envelope)),
		Ciphertext:           mkemCiphertext.Envelope,
	}

	// Serialize CourierEnvelope
	courierEnvelopeBytes, err := courierEnvelope.MarshalBinary()
	require.NoError(t, err)

	// Verify it fits in a Box
	require.LessOrEqual(t, len(courierEnvelopeBytes), boxPayloadLength,
		"CourierEnvelope with max plaintext should fit in Box")

	t.Logf("Actual CourierEnvelope size: %d bytes", len(courierEnvelopeBytes))
	t.Logf("Remaining space in Box: %d bytes", boxPayloadLength-len(courierEnvelopeBytes))

	// Test that plaintext larger than max fails to fit
	oversizedPlaintext := make([]byte, maxPlaintext+100)
	_, err = rand.Reader.Read(oversizedPlaintext)
	require.NoError(t, err)

	// This should produce a CourierEnvelope that's too large
	boxID2, bacapCiphertext2, sigRaw2, err := destWriter.EncryptNext(oversizedPlaintext)
	require.NoError(t, err)

	// Convert signature to fixed-size array
	var sig2 [64]uint8
	copy(sig2[:], sigRaw2)

	replicaWrite2 := &pigeonhole.ReplicaWrite{
		BoxID:      boxID2,
		Signature:  sig2,
		PayloadLen: uint32(len(bacapCiphertext2)),
		Payload:    bacapCiphertext2,
	}

	replicaInnerMsg2 := &pigeonhole.ReplicaInnerMessage{
		MessageType: 1,
		WriteMsg:    replicaWrite2,
	}
	replicaInnerBytes2, err := replicaInnerMsg2.MarshalBinary()
	require.NoError(t, err)

	_, mkemCiphertext2 := mkemScheme.Encapsulate(replicaKeys, replicaInnerBytes2)

	courierEnvelope2 := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1},
		Dek1:                 *mkemCiphertext2.DEKCiphertexts[0],
		Dek2:                 *mkemCiphertext2.DEKCiphertexts[1],
		ReplyIndex:           0,
		Epoch:                0,
		SenderPubkeyLen:      uint16(len(ephPriv.Public().Bytes())),
		SenderPubkey:         ephPriv.Public().Bytes(),
		CiphertextLen:        uint32(len(mkemCiphertext2.Envelope)),
		Ciphertext:           mkemCiphertext2.Envelope,
	}

	courierEnvelopeBytes2, err := courierEnvelope2.MarshalBinary()
	require.NoError(t, err)

	// Verify it does NOT fit in a Box
	require.Greater(t, len(courierEnvelopeBytes2), boxPayloadLength,
		"CourierEnvelope with oversized plaintext should NOT fit in Box")

	t.Logf("Oversized CourierEnvelope size: %d bytes (exceeds box by %d bytes)",
		len(courierEnvelopeBytes2), len(courierEnvelopeBytes2)-boxPayloadLength)
}
