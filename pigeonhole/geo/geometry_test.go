// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package geo

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/pigeonhole"
	"github.com/stretchr/testify/require"
)

func TestGeometryUseCase1FromBoxPayloadLength(t *testing.T) {
	// Use Case 1: Given BoxPayloadLength, derive all envelope sizes
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	boxPayloadLength := 1000
	g := NewGeometry(boxPayloadLength, nikeScheme)

	require.NoError(t, g.Validate())
	require.Equal(t, boxPayloadLength, g.BoxPayloadLength)
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
	pigeonholeGeo := NewGeometry(500, nikeScheme)
	require.NoError(t, pigeonholeGeo.Validate())

	// Derive a Sphinx geometry that can accommodate it
	sphinxGeo := pigeonholeGeo.ToSphinxGeometry(5, true) // 5 hops, with SURB
	require.NoError(t, sphinxGeo.Validate())

	// The Sphinx geometry should be able to fit our largest envelope
	maxEnvelopeSize := maxInt(
		pigeonholeGeo.CourierQueryReadLength,
		pigeonholeGeo.CourierQueryWriteLength,
		pigeonholeGeo.CourierQueryReplyReadLength,
		pigeonholeGeo.CourierQueryReplyWriteLength,
	)

	require.GreaterOrEqual(t, sphinxGeo.UserForwardPayloadLength, maxEnvelopeSize)

	t.Logf("Pigeonhole max envelope size: %d", maxEnvelopeSize)
	t.Logf("Sphinx UserForwardPayloadLength: %d", sphinxGeo.UserForwardPayloadLength)
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
	pigeonholeGeo, err := NewGeometryFromSphinx(sphinxGeo, nikeScheme)
	require.NoError(t, err)
	require.NoError(t, pigeonholeGeo.Validate())

	// The largest envelope should fit within the Sphinx constraint
	maxEnvelopeSize := maxInt(
		pigeonholeGeo.CourierQueryReadLength,
		pigeonholeGeo.CourierQueryWriteLength,
		pigeonholeGeo.CourierQueryReplyReadLength,
		pigeonholeGeo.CourierQueryReplyWriteLength,
	)

	require.LessOrEqual(t, maxEnvelopeSize, sphinxGeo.UserForwardPayloadLength)

	// The BoxPayloadLength should be optimized (not too small)
	require.Greater(t, pigeonholeGeo.BoxPayloadLength, 100) // Should find a reasonable size

	t.Logf("Sphinx UserForwardPayloadLength: %d", sphinxGeo.UserForwardPayloadLength)
	t.Logf("Optimal BoxPayloadLength: %d", pigeonholeGeo.BoxPayloadLength)
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
			g := NewGeometry(boxPayloadLength, nikeScheme)
			require.NoError(t, g.Validate())

			// With trunnel, calculations should be perfectly deterministic
			g2 := NewGeometry(boxPayloadLength, nikeScheme)
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
	pigeonholeGeo1 := NewGeometry(originalBoxPayloadLength, nikeScheme)

	// Convert to Sphinx geometry
	sphinxGeo := pigeonholeGeo1.ToSphinxGeometry(5, true)

	// Convert back to pigeonhole geometry
	pigeonholeGeo2, err := NewGeometryFromSphinx(sphinxGeo, nikeScheme)
	require.NoError(t, err)

	// The round-trip should give us a BoxPayloadLength that's at least as good as the original
	require.GreaterOrEqual(t, pigeonholeGeo2.BoxPayloadLength, originalBoxPayloadLength)

	t.Logf("Original BoxPayloadLength: %d", originalBoxPayloadLength)
	t.Logf("Round-trip BoxPayloadLength: %d", pigeonholeGeo2.BoxPayloadLength)
	t.Logf("Sphinx UserForwardPayloadLength: %d", sphinxGeo.UserForwardPayloadLength)
}

func TestGeometryPrecisePredictions(t *testing.T) {
	// Test that geometry predictions exactly match actual serialized message sizes
	// This test creates real messages like the integration tests do
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	g := NewGeometry(4559, nikeScheme) // Use the same BoxPayloadLength as integration test
	require.NoError(t, g.Validate())

	// Create BACAP keys like integration tests
	aliceOwner, err := bacap.NewBoxOwnerCap(rand.Reader)
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
		paddedPayload, err := pigeonhole.CreatePaddedPayload(testMessage, g.BoxPayloadLength)
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
			IsRead:               0, // 0 = write, 1 = read
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
		t.Logf("BoxPayloadLength: %d bytes", g.BoxPayloadLength)
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
		const isReadSize = 1               // uint8

		expectedFixedOverhead := intermediateReplicasSize + dek1Size + dek2Size +
			replyIndexSize + epochSize + senderPubkeyLenSize + ciphertextLenSize + isReadSize
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
		paddedPayload, err := pigeonhole.CreatePaddedPayload(testMessage, g.BoxPayloadLength)
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
			IsRead:               0,
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
		const isReadSize = 1               // uint8

		expectedCourierEnvelopeOverhead := intermediateReplicasSize + dek1Size + dek2Size +
			replyIndexSize + epochSize + senderPubkeyLenSize + ciphertextLenSize + isReadSize + len(senderPubkeyBytes)

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

		g := NewGeometry(4559, nikeScheme)

		// Manually calculate what the geometry should be
		// Step 1: BACAP payload (padded payload already includes length prefix)
		bacapPayloadSize := g.BoxPayloadLength + 16 // bacapEncryptionOverhead
		t.Logf("Step 1 - BACAP payload: %d + 16 = %d", g.BoxPayloadLength, bacapPayloadSize)

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
		courierEnvelopeFixedOverhead := 2 + 60 + 60 + 1 + 8 + 2 + 4 + 1 // All fixed fields
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

		g := NewGeometry(4551, nikeScheme) // BoxPayloadLength from integration test

		t.Logf("Integration test geometry:")
		t.Logf("  BoxPayloadLength: %d", g.BoxPayloadLength)
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
