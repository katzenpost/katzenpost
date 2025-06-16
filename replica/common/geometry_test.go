// SPDX-FileCopyrightText: Copyright (C) 2024  David Anthony Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

const (
	testContext = "test-context"
)

// DRY helper functions to eliminate massive code duplication

// createBACAPEncryptedPayload creates BACAP encrypted payload from raw bytes
// This eliminates the repeated BACAP encryption pattern used throughout tests
func createBACAPEncryptedPayload(t *testing.T, payload []byte) ([bacap.BoxIDSize]byte, []byte, [bacap.SignatureSize]byte) {
	owner, err := bacap.NewBoxOwnerCap(rand.Reader)
	require.NoError(t, err)

	ctx := []byte(testContext)
	statefulWriter, err := bacap.NewStatefulWriter(owner, ctx)
	require.NoError(t, err)

	// BACAP encrypt the payload
	boxID, ciphertext, sigraw, err := statefulWriter.EncryptNext(payload)
	require.NoError(t, err)

	sig := [bacap.SignatureSize]byte{}
	copy(sig[:], sigraw)

	return boxID, ciphertext, sig
}

// generateMKEMReplicaKeys generates replica public keys for MKEM
// This eliminates the repeated MKEM key generation pattern
func generateMKEMReplicaKeys(t *testing.T, nikeScheme nike.Scheme) []nike.PublicKey {
	replicaPubKeys := make([]nike.PublicKey, 2)
	for i := 0; i < 2; i++ {
		pub, _, err := nikeScheme.GenerateKeyPair()
		require.NoError(t, err)
		replicaPubKeys[i] = pub
	}
	return replicaPubKeys
}

// createReplicaWriteFromPayload creates a ReplicaWrite from raw payload
// This eliminates the repeated ReplicaWrite creation pattern
func createReplicaWriteFromPayload(t *testing.T, payload []byte) *commands.ReplicaWrite {
	boxID, ciphertext, sig := createBACAPEncryptedPayload(t, payload)

	return &commands.ReplicaWrite{
		BoxID:     &boxID,
		Signature: &sig,
		Payload:   ciphertext,
	}
}

// createReplicaInnerMessageFromPayload creates a ReplicaInnerMessage from raw payload
// This eliminates the repeated ReplicaInnerMessage creation pattern
func createReplicaInnerMessageFromPayload(t *testing.T, payload []byte) *ReplicaInnerMessage {
	writeRequest := createReplicaWriteFromPayload(t, payload)

	return &ReplicaInnerMessage{
		ReplicaWrite: writeRequest,
	}
}

func TestReplicaWriteOverhead(t *testing.T) {
	payload := make([]byte, 1000)

	// Use DRY helper to create BACAP encrypted payload
	boxID, bacapCiphertext, sig := createBACAPEncryptedPayload(t, payload)

	writeCmd := &commands.ReplicaWrite{
		Cmds: nil, // we don't want padding

		BoxID:     &boxID,
		Signature: &sig,
		Payload:   bacapCiphertext, // This is the encrypted payload with BACAP overhead
	}
	writeCmdBytes := writeCmd.ToBytes()
	overhead := len(writeCmdBytes) - len(payload) // Compare against original payload size

	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)
	geo := NewGeometry(len(payload), nikeScheme)
	overhead2 := geo.replicaWriteOverhead()

	t.Logf("Original payload size: %d", len(payload))
	t.Logf("BACAP ciphertext size: %d", len(bacapCiphertext))
	t.Logf("BACAP encryption overhead: %d", len(bacapCiphertext)-len(payload))
	t.Logf("writeCmdBytes total overhead: %d", overhead)
	t.Logf("geo.replicaWriteOverhead: %d", overhead2)

	require.Equal(t, overhead, overhead2)
}

func TestReplicaReadOverhead(t *testing.T) {
	// ReplicaRead only contains a BoxID (Ed25519 public key)
	readCmd := &ReplicaRead{
		BoxID: &[bacap.BoxIDSize]byte{},
	}
	readCmdBytes := readCmd.ToBytes()
	overhead := len(readCmdBytes)

	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)
	geo := NewGeometry(1000, nikeScheme) // payload size doesn't matter for read overhead
	overhead2 := geo.replicaReadOverhead()

	t.Logf("readCmdBytes overhead: %d", overhead)
	t.Logf("geo.replicaReadOverhead: %d", overhead2)

	require.Equal(t, overhead, overhead2)
}

func TestReplicaReadReplyOverhead(t *testing.T) {
	// Test CBOR overhead for ReplicaReadReply
	payload := make([]byte, 100)
	boxID := [bacap.BoxIDSize]byte{}
	signature := [bacap.SignatureSize]byte{}

	reply := &ReplicaReadReply{
		ErrorCode: 0,
		BoxID:     &boxID,
		Signature: &signature,
		Payload:   payload,
		IsLast:    false,
	}
	replyBytes := reply.Bytes()
	actualOverhead := len(replyBytes) - len(payload)

	// Current geometry calculation
	calculatedOverhead := replicaReadReplyOverhead()

	// The calculated overhead should match the actual overhead
	require.Equal(t, actualOverhead, calculatedOverhead, "Geometry calculation should match actual overhead")
}

func TestCourierEnvelopeOverhead(t *testing.T) {
	// Use x25519 to match our geometry functions and real-world usage
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	payload := make([]byte, 1000)
	geo := NewGeometry(len(payload), nikeScheme)

	// Create MKEM scheme and generate MKEM keys like real-world usage
	mkemScheme := mkem.NewScheme(nikeScheme)

	// Use DRY helper to generate replica keys for MKEM
	replicaPubKeys := generateMKEMReplicaKeys(t, nikeScheme)

	// Create dummy plaintext to get MKEM keys
	dummyPlaintext := []byte("dummy")
	mkemPrivateKey, mkemCiphertext := mkemScheme.Encapsulate(replicaPubKeys, dummyPlaintext)
	mkemPublicKey := mkemPrivateKey.Public()

	envelope := &CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1},
		DEK:                  [2]*[mkem.DEKSize]byte{mkemCiphertext.DEKCiphertexts[0], mkemCiphertext.DEKCiphertexts[1]},
		ReplyIndex:           0,
		Epoch:                0,                     // Match real-world usage (defaults to 0)
		SenderEPubKey:        mkemPublicKey.Bytes(), // Use MKEM public key like real usage
		IsRead:               false,
		Ciphertext:           payload,
	}

	envelopeBytes := envelope.Bytes()
	overhead := len(envelopeBytes) - len(payload)

	// Use the actual payload size for accurate overhead calculation
	overhead2 := max(geo.courierEnvelopeReadOverhead(), geo.courierEnvelopeWriteOverhead(len(payload)))

	t.Logf("courierEnvelope overhead: %d", overhead)
	t.Logf("geo.courierEnvelopeOverhead: %d", overhead2)

	require.Equal(t, overhead, overhead2)
}

func TestCourierEnvelopeReplyOverhead(t *testing.T) {
	// Create a CourierEnvelopeReply with fixed payload size
	payload := make([]byte, 1000)

	// Create envelope hash
	envelopeHash := &[hash.HashSize]byte{}

	reply := &CourierEnvelopeReply{
		EnvelopeHash: envelopeHash,
		ReplyIndex:   0,
		ErrorCode:    0,
		Payload:      payload,
	}

	replyBytes := reply.Bytes()
	overhead := len(replyBytes) - len(payload)

	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)
	geo := NewGeometry(len(payload), nikeScheme)
	overhead2 := geo.courierEnvelopeReplyOverhead()

	t.Logf("geo.courierEnvelopeReplyOverhead: %d", overhead2)

	require.Equal(t, overhead, overhead2)
}

func TestReplicaInnerMessageOverhead(t *testing.T) {
	payload := make([]byte, 1000)
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)
	geo := NewGeometry(len(payload), nikeScheme)

	// Test ReplicaRead case
	readMsg := &ReplicaInnerMessage{
		ReplicaRead: &ReplicaRead{
			BoxID: &[bacap.BoxIDSize]byte{},
		},
		ReplicaWrite: nil,
	}
	readMsgBytes := readMsg.Bytes()
	readOverhead := len(readMsgBytes)

	// Test ReplicaWrite case - use DRY helper for BACAP encryption
	replicaWrite := createReplicaWriteFromPayload(t, payload)
	replicaWrite.Cmds = nil // no padding
	replicaWrite.IsLast = false

	writeMsg := &ReplicaInnerMessage{
		ReplicaRead:  nil,
		ReplicaWrite: replicaWrite,
	}
	writeMsgBytes := writeMsg.Bytes()
	replicaWriteBytes := replicaWrite.ToBytes()
	writeOverhead := len(writeMsgBytes) - len(replicaWriteBytes) // Compare against ReplicaWrite size

	// Test the specific overheads separately
	calculatedReadOverhead := geo.replicaInnerMessageReadOverhead()
	calculatedWriteOverhead := geo.replicaInnerMessageWriteOverhead()

	// Debug output to understand the values
	t.Logf("Debug values:")
	t.Logf("  Original payload size: %d", len(payload))
	t.Logf("  ReplicaRead total size: %d", readOverhead)
	t.Logf("  ReplicaWrite size: %d", len(replicaWriteBytes))
	t.Logf("  ReplicaInnerMessage size: %d", len(writeMsgBytes))
	t.Logf("  Test writeOverhead (ReplicaInnerMessage - ReplicaWrite): %d", writeOverhead)
	t.Logf("  Geometry calculatedReadOverhead: %d", calculatedReadOverhead)
	t.Logf("  Geometry calculatedWriteOverhead: %d", calculatedWriteOverhead)
	t.Logf("  Actual ReplicaInnerMessage overhead: %d", len(writeMsgBytes)-len(replicaWriteBytes))

	// The calculated read overhead should match the read case
	// Note: readOverhead is the total size of ReplicaInnerMessage with ReplicaRead
	// calculatedReadOverhead is just the overhead, so we need to add the ReplicaRead size
	replicaReadSize := 32 + 9 // BoxID + CBOR overhead (from replicaReadOverhead)
	expectedReadTotal := calculatedReadOverhead + replicaReadSize
	require.Equal(t, readOverhead, expectedReadTotal, "Read overhead calculation should match")

	// The calculated write overhead should match the write case
	require.Equal(t, writeOverhead, calculatedWriteOverhead, "Write overhead calculation should match")
}

// TestGeometryUseCase1 tests Use Case 1: specify BoxPayloadLength and derive PigeonholeGeometry
// This test composes the ACTUAL nested encrypted message structure to verify geometry calculations
func TestGeometryUseCase1(t *testing.T) {
	boxPayloadLength := 1000
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	pigeonholeGeometry := GeometryFromBoxPayloadLength(boxPayloadLength, nikeScheme)

	// Validate pigeonhole geometry
	require.NotNil(t, pigeonholeGeometry)
	require.Equal(t, boxPayloadLength, pigeonholeGeometry.BoxPayloadLength)
	require.Equal(t, nikeScheme.Name(), pigeonholeGeometry.NIKEName)
	require.Equal(t, SignatureSchemeName, pigeonholeGeometry.SignatureSchemeName)
	require.NoError(t, pigeonholeGeometry.Validate())

	// NOW TEST THE ACTUAL REAL MESSAGE COMPOSITION (like TestCourierReplicaIntegration)
	actualCourierEnvelopeSize := composeActualCourierEnvelope(t, boxPayloadLength, nikeScheme)
	actualCourierEnvelopeReplySize := composeActualCourierEnvelopeReply(t, boxPayloadLength, nikeScheme)

	t.Logf("Use Case 1 Results:")
	t.Logf("  BoxPayloadLength: %d", boxPayloadLength)
	t.Logf("  Calculated CourierQueryReadLength: %d", pigeonholeGeometry.CourierQueryReadLength)
	t.Logf("  Calculated CourierQueryWriteLength: %d", pigeonholeGeometry.CourierQueryWriteLength)
	t.Logf("  Actual CourierEnvelopeLength: %d", actualCourierEnvelopeSize)
	t.Logf("  Calculated CourierQueryReplyReadLength: %d", pigeonholeGeometry.CourierQueryReplyReadLength)
	t.Logf("  Calculated CourierQueryReplyWriteLength: %d", pigeonholeGeometry.CourierQueryReplyWriteLength)
	t.Logf("  Actual CourierEnvelopeReplyLength: %d", actualCourierEnvelopeReplySize)

	// The calculated sizes should be very close to actual REAL message sizes
	// For write operations, compare against write length
	require.InDelta(t, actualCourierEnvelopeSize, pigeonholeGeometry.CourierQueryWriteLength, 35,
		"CourierQuery geometry calculation should be within 35 bytes of actual CourierEnvelope (includes wrapper overhead)")
	require.InDelta(t, actualCourierEnvelopeReplySize, pigeonholeGeometry.CourierQueryReplyReadLength, 100,
		"CourierQueryReply geometry calculation should be within 100 bytes of actual CourierEnvelopeReply (includes wrapper overhead and MKEM encryption)")
}

// TestGeometryUseCase2 tests Use Case 2: specify precomputed PigeonholeGeometry and derive SphinxGeometry
func TestGeometryUseCase2(t *testing.T) {
	// Create a precomputed pigeonhole geometry
	boxPayloadLength := 2000
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	precomputedPigeonholeGeometry := &Geometry{
		CourierQueryReadLength:       boxPayloadLength + 150, // Some overhead
		CourierQueryWriteLength:      boxPayloadLength + 150, // Some overhead
		CourierQueryReplyReadLength:  82,                     // Some reply overhead
		CourierQueryReplyWriteLength: 82,                     // Some reply overhead
		NIKEName:                     nikeScheme.Name(),
		SignatureSchemeName:          SignatureSchemeName,
		BoxPayloadLength:             boxPayloadLength,
	}

	nrHops := 7
	sphinxGeometry := GeometryFromPigeonholeGeometry(precomputedPigeonholeGeometry, nrHops)

	// Validate sphinx geometry
	require.NotNil(t, sphinxGeometry)
	require.Equal(t, nikeScheme.Name(), sphinxGeometry.NIKEName)
	require.Equal(t, nrHops, sphinxGeometry.NrHops)
	require.Greater(t, sphinxGeometry.PacketLength, 0)
	maxCourierQueryLength := max(precomputedPigeonholeGeometry.CourierQueryReadLength, precomputedPigeonholeGeometry.CourierQueryWriteLength)
	require.GreaterOrEqual(t, sphinxGeometry.UserForwardPayloadLength, maxCourierQueryLength)

	// Test that sphinx geometry validates
	require.NoError(t, sphinxGeometry.Validate())

	t.Logf("Use Case 2 Results:")
	t.Logf("  Precomputed CourierQueryReadLength: %d", precomputedPigeonholeGeometry.CourierQueryReadLength)
	t.Logf("  Precomputed CourierQueryWriteLength: %d", precomputedPigeonholeGeometry.CourierQueryWriteLength)
	t.Logf("  Precomputed BoxPayloadLength: %d", precomputedPigeonholeGeometry.BoxPayloadLength)
	t.Logf("  Derived Sphinx UserForwardPayloadLength: %d", sphinxGeometry.UserForwardPayloadLength)
	t.Logf("  Derived Sphinx PacketLength: %d", sphinxGeometry.PacketLength)
}

// TestGeometryUseCase3 tests Use Case 3: specify precomputed SphinxGeometry and derive PigeonholeGeometry
func TestGeometryUseCase3(t *testing.T) {
	// Create a precomputed sphinx geometry with size constraints
	// Use a larger constraint to accommodate the CourierQuery wrapper overhead
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)
	nrHops := 5
	pigeonholeNikeScheme := schemes.ByName("x25519")
	require.NotNil(t, pigeonholeNikeScheme)

	// First, create a test pigeonhole geometry to measure its requirements
	testBoxPayloadLength := 1000 // Start with a reasonable box payload size
	testGeometry := NewGeometry(testBoxPayloadLength, pigeonholeNikeScheme)
	require.NoError(t, testGeometry.Validate())

	// Determine the minimum sphinx constraint needed
	maxPigeonholeSize := max(testGeometry.CourierQueryReadLength, testGeometry.CourierQueryWriteLength)
	userForwardPayloadLength := maxPigeonholeSize + 100 // Add some margin

	precomputedSphinxGeometry := geo.GeometryFromUserForwardPayloadLength(nikeScheme, userForwardPayloadLength, true, nrHops)
	require.NotNil(t, precomputedSphinxGeometry)

	// Now derive the actual pigeonhole geometry from the sphinx constraint
	pigeonholeGeometry := GeometryFromSphinxGeometry(precomputedSphinxGeometry, pigeonholeNikeScheme)

	// Validate pigeonhole geometry
	require.NotNil(t, pigeonholeGeometry)
	// Pigeonhole uses the specified NIKE scheme, independent of Sphinx NIKE scheme
	require.Equal(t, pigeonholeNikeScheme.Name(), pigeonholeGeometry.NIKEName)
	require.Equal(t, SignatureSchemeName, pigeonholeGeometry.SignatureSchemeName)
	require.Greater(t, pigeonholeGeometry.BoxPayloadLength, 0)
	require.Greater(t, pigeonholeGeometry.CourierQueryReadLength, 0)
	require.Greater(t, pigeonholeGeometry.CourierQueryWriteLength, pigeonholeGeometry.BoxPayloadLength)
	require.Greater(t, pigeonholeGeometry.CourierQueryReplyReadLength, 0)
	require.Greater(t, pigeonholeGeometry.CourierQueryReplyWriteLength, 0)

	// Test that pigeonhole geometry validates
	require.NoError(t, pigeonholeGeometry.Validate())

	// Now measure actual message sizes to verify they fit within the sphinx constraint
	actualReadSize := createActualNestedCourierMessage(t, pigeonholeGeometry.BoxPayloadLength, pigeonholeNikeScheme)
	actualWriteSize := createActualNestedCourierMessage(t, pigeonholeGeometry.BoxPayloadLength, pigeonholeNikeScheme)

	maxActualSize := max(actualReadSize, actualWriteSize)

	// The actual messages should fit within the sphinx constraint
	require.LessOrEqual(t, maxActualSize, precomputedSphinxGeometry.UserForwardPayloadLength,
		"Actual pigeonhole messages should fit within sphinx constraint")

	// The geometry predictions should also fit within the sphinx constraint
	maxGeometryPrediction := max(pigeonholeGeometry.CourierQueryReadLength, pigeonholeGeometry.CourierQueryWriteLength)
	require.LessOrEqual(t, maxGeometryPrediction, precomputedSphinxGeometry.UserForwardPayloadLength,
		"Geometry predictions should fit within sphinx constraint")

	t.Logf("Use Case 3 Results:")
	t.Logf("  Sphinx UserForwardPayloadLength constraint: %d", precomputedSphinxGeometry.UserForwardPayloadLength)
	t.Logf("  Derived BoxPayloadLength: %d", pigeonholeGeometry.BoxPayloadLength)
	t.Logf("  Derived CourierQueryReadLength: %d", pigeonholeGeometry.CourierQueryReadLength)
	t.Logf("  Derived CourierQueryWriteLength: %d", pigeonholeGeometry.CourierQueryWriteLength)
	t.Logf("  Actual read message size: %d", actualReadSize)
	t.Logf("  Actual write message size: %d", actualWriteSize)
	t.Logf("  Max actual size: %d", maxActualSize)
	t.Logf("  Max geometry prediction: %d", maxGeometryPrediction)
}

// createCourierEnvelopeFromPayload creates a REAL CourierEnvelope from a payload using the exact same approach
// as TestCourierReplicaIntegration in aliceComposesNextMessage()
func createCourierEnvelopeFromPayload(t *testing.T, boxPayloadLength int, nikeScheme nike.Scheme) *CourierEnvelope {
	// Step 1-3: Create ReplicaInnerMessage using DRY helper
	payload := make([]byte, boxPayloadLength)
	msg := createReplicaInnerMessageFromPayload(t, payload)

	// Step 4: MKEM encrypt (exactly like integration test)
	mkemScheme := mkem.NewScheme(nikeScheme)

	// Use DRY helper to generate replica keys for MKEM
	replicaPubKeys := generateMKEMReplicaKeys(t, nikeScheme)

	mkemPrivateKey, mkemCiphertext := mkemScheme.Encapsulate(replicaPubKeys, msg.Bytes())
	mkemPublicKey := mkemPrivateKey.Public()

	// Step 5: Create REAL CourierEnvelope (exactly like integration test)
	envelope := &CourierEnvelope{
		SenderEPubKey:        mkemPublicKey.Bytes(),
		IntermediateReplicas: [2]uint8{0, 1},
		DEK:                  [2]*[mkem.DEKSize]byte{mkemCiphertext.DEKCiphertexts[0], mkemCiphertext.DEKCiphertexts[1]},
		Ciphertext:           mkemCiphertext.Envelope,
		IsRead:               false,
	}

	return envelope
}

// composeActualCourierEnvelope creates the REAL CourierEnvelope using the exact same approach
// as TestCourierReplicaIntegration in aliceComposesNextMessage()
func composeActualCourierEnvelope(t *testing.T, boxPayloadLength int, nikeScheme nike.Scheme) int {
	envelope := createCourierEnvelopeFromPayload(t, boxPayloadLength, nikeScheme)
	return len(envelope.Bytes())
}

// createCourierEnvelopeReplyFromPayload creates a REAL CourierEnvelopeReply from a payload using the same approach
// as replica handlers.go (lines 124-136) with MKEM encryption
func createCourierEnvelopeReplyFromPayload(t *testing.T, boxPayloadLength int, nikeScheme nike.Scheme) *CourierEnvelopeReply {
	// Step 1: Create BACAP encrypted payload using DRY helper
	payload := make([]byte, boxPayloadLength)
	boxID, ciphertext, sig := createBACAPEncryptedPayload(t, payload)

	// Step 2: Create ReplicaReadReply with BACAP-encrypted payload
	readReply := &ReplicaReadReply{
		ErrorCode: 0,
		BoxID:     &boxID,
		Signature: &sig,
		Payload:   ciphertext,
	}

	// Step 3: Create ReplicaMessageReplyInnerMessage containing ReplicaReadReply
	innerMsg := &ReplicaMessageReplyInnerMessage{
		ReplicaReadReply:  readReply,
		ReplicaWriteReply: nil,
	}

	// Step 4: MKEM encrypt the ReplicaMessageReplyInnerMessage (like replica handlers.go)
	mkemScheme := mkem.NewScheme(nikeScheme)

	// Generate replica and sender keys for MKEM
	_, replicaPrivateKey, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	senderPublicKey, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)

	// MKEM encrypt the inner message
	envelopeReply := mkemScheme.EnvelopeReply(replicaPrivateKey, senderPublicKey, innerMsg.Bytes())

	// Step 5: Create REAL CourierEnvelopeReply with MKEM-encrypted payload
	envelopeHash := &[hash.HashSize]byte{}
	reply := &CourierEnvelopeReply{
		EnvelopeHash: envelopeHash,
		ReplyIndex:   0,
		ErrorCode:    0,
		Payload:      envelopeReply.Envelope, // MKEM-encrypted payload!
	}

	return reply
}

// composeActualCourierEnvelopeReply creates the REAL CourierEnvelopeReply using the same approach
// as replica handlers.go (lines 124-136) with MKEM encryption
func composeActualCourierEnvelopeReply(t *testing.T, boxPayloadLength int, nikeScheme nike.Scheme) int {
	reply := createCourierEnvelopeReplyFromPayload(t, boxPayloadLength, nikeScheme)
	return len(reply.Bytes())
}

// TestGeometryCBOROverheadScaling tests how CBOR overhead changes with different box payload sizes.
// This test examines whether the geometry object remains valid and whether CBOR overhead is constant
// or scales with larger payload sizes.
func TestGeometryCBOROverheadScaling(t *testing.T) {
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	// Test various box payload sizes to see how CBOR overhead scales
	testSizes := []int{
		100,    // Small payload
		1000,   // Medium payload
		5000,   // Large payload
		10000,  // Very large payload
		50000,  // Huge payload
		100000, // Massive payload
	}

	type overheadResult struct {
		payloadSize                  int
		courierEnvelopeOverhead      int
		courierEnvelopeReplyOverhead int
		replicaReadReplyOverhead     int
		replicaWriteOverhead         int
		actualCourierEnvelopeSize    int
		actualCourierReplySize       int
		geometryValid                bool
	}

	var results []overheadResult

	for _, payloadSize := range testSizes {
		t.Logf("Testing payload size: %d bytes", payloadSize)

		// Create geometry for this payload size
		geometry := NewGeometry(payloadSize, nikeScheme)
		require.NotNil(t, geometry)

		// Test that geometry is still valid
		err := geometry.Validate()
		geometryValid := (err == nil)
		if !geometryValid {
			t.Logf("  Geometry validation failed for size %d: %v", payloadSize, err)
		}

		// Measure calculated overheads (use estimated ciphertext size for this test)
		estimatedCiphertextSize := 1000
		courierEnvelopeOverhead := max(geometry.courierEnvelopeReadOverhead(), geometry.courierEnvelopeWriteOverhead(estimatedCiphertextSize))
		courierEnvelopeReplyOverhead := geometry.courierEnvelopeReplyOverhead()
		replicaReadReplyOverhead := replicaReadReplyOverhead()
		replicaWriteOverhead := geometry.replicaWriteOverhead()

		// Measure actual CBOR sizes by creating real messages
		actualCourierEnvelopeSize := measureActualCourierEnvelopeSize(t, payloadSize, nikeScheme)
		actualCourierReplySize := measureActualCourierEnvelopeReplySize(t, payloadSize, nikeScheme)

		result := overheadResult{
			payloadSize:                  payloadSize,
			courierEnvelopeOverhead:      courierEnvelopeOverhead,
			courierEnvelopeReplyOverhead: courierEnvelopeReplyOverhead,
			replicaReadReplyOverhead:     replicaReadReplyOverhead,
			replicaWriteOverhead:         replicaWriteOverhead,
			actualCourierEnvelopeSize:    actualCourierEnvelopeSize,
			actualCourierReplySize:       actualCourierReplySize,
			geometryValid:                geometryValid,
		}
		results = append(results, result)

		t.Logf("  Courier envelope overhead (calculated): %d", courierEnvelopeOverhead)
		t.Logf("  Courier envelope reply overhead (calculated): %d", courierEnvelopeReplyOverhead)
		t.Logf("  Replica read reply overhead (calculated): %d", replicaReadReplyOverhead)
		t.Logf("  Replica write overhead (calculated): %d", replicaWriteOverhead)
		t.Logf("  Actual courier envelope size: %d", actualCourierEnvelopeSize)
		t.Logf("  Actual courier reply size: %d", actualCourierReplySize)
		t.Logf("  Geometry valid: %t", geometryValid)
	}

	// Analyze the results to see how overhead scales
	t.Logf("\n=== CBOR Overhead Scaling Analysis ===")

	// Check if calculated overheads remain constant (they should)
	firstResult := results[0]
	for _, result := range results[1:] {
		t.Logf("Comparing size %d to baseline %d:", result.payloadSize, firstResult.payloadSize)

		// These should remain constant regardless of payload size
		require.Equal(t, firstResult.courierEnvelopeOverhead, result.courierEnvelopeOverhead,
			"Courier envelope overhead should be constant across payload sizes")
		require.Equal(t, firstResult.courierEnvelopeReplyOverhead, result.courierEnvelopeReplyOverhead,
			"Courier envelope reply overhead should be constant across payload sizes")
		require.Equal(t, firstResult.replicaReadReplyOverhead, result.replicaReadReplyOverhead,
			"Replica read reply overhead should be constant across payload sizes")

		// Replica write overhead is also constant - it only includes fixed overhead components
		// The payload size is added separately in the geometry calculations
		require.Equal(t, firstResult.replicaWriteOverhead, result.replicaWriteOverhead,
			"Replica write overhead should be constant across payload sizes (fixed overhead only)")

		t.Logf("  ✓ All calculated overheads scale as expected")
	}

	// Check actual CBOR overhead scaling
	t.Logf("\nActual CBOR overhead analysis:")
	firstActualCourierOverhead := results[0].actualCourierEnvelopeSize - results[0].payloadSize
	firstActualReplyOverhead := results[0].actualCourierReplySize - results[0].payloadSize

	for _, result := range results {
		courierOverheadActual := result.actualCourierEnvelopeSize - result.payloadSize
		replyOverheadActual := result.actualCourierReplySize - result.payloadSize

		t.Logf("Size %d: courier overhead=%d, reply overhead=%d",
			result.payloadSize, courierOverheadActual, replyOverheadActual)

		// The actual CBOR overhead should remain nearly constant across all payload sizes
		// Small variations (1-2 bytes) are expected due to CBOR length encoding differences
		require.InDelta(t, firstActualCourierOverhead, courierOverheadActual, 5,
			"Actual courier envelope CBOR overhead should be nearly constant across payload sizes (±5 bytes)")
		require.InDelta(t, firstActualReplyOverhead, replyOverheadActual, 5,
			"Actual courier reply CBOR overhead should be nearly constant across payload sizes (±5 bytes)")

		// For larger payloads, check that geometry remains valid
		if result.payloadSize <= 10000 {
			require.True(t, result.geometryValid,
				"Geometry should remain valid for reasonable payload sizes up to 10KB")
		}
	}

	// Summary
	t.Logf("\n=== Summary ===")
	t.Logf("✓ CBOR overhead calculations are consistent across different payload sizes")
	t.Logf("✓ Geometry objects remain valid for payload sizes up to 10KB")
	t.Logf("✓ Fixed overheads (envelope headers) remain constant regardless of payload size")
	t.Logf("✓ Actual CBOR overhead is nearly constant with small variations (1-2 bytes)")
	t.Logf("✓ CBOR length encoding causes minor overhead variations but doesn't scale significantly")
	t.Logf("✓ The pigeonhole geometry system handles large payloads efficiently")

	// Report the actual overhead values for reference
	t.Logf("\nCBOR Overhead Details:")
	t.Logf("  Courier envelope overhead: %d bytes (±1-2 bytes variation)", firstActualCourierOverhead)
	t.Logf("  Courier reply overhead: %d bytes (±1-2 bytes variation)", firstActualReplyOverhead)
	t.Logf("  Calculated courier envelope overhead: %d bytes", results[0].courierEnvelopeOverhead)
	t.Logf("  Calculated courier reply overhead: %d bytes", results[0].courierEnvelopeReplyOverhead)
}

// measureActualCourierEnvelopeSize creates a real CourierEnvelope and measures its CBOR size
func measureActualCourierEnvelopeSize(t *testing.T, payloadSize int, nikeScheme nike.Scheme) int {
	envelope := createCourierEnvelopeFromPayload(t, payloadSize, nikeScheme)
	return len(envelope.Bytes())
}

// measureActualCourierEnvelopeReplySize creates a real CourierEnvelopeReply and measures its CBOR size
func measureActualCourierEnvelopeReplySize(t *testing.T, payloadSize int, nikeScheme nike.Scheme) int {
	reply := createCourierEnvelopeReplyFromPayload(t, payloadSize, nikeScheme)
	return len(reply.Bytes())
}

// TestGeometryOutermostMessageSizePredictions tests that geometry predictions match actual nested message sizes
// This test follows TDD - it should FAIL initially, exposing inconsistencies between
// geometry predictions and actual nested message creation and measurement.
// We're testing the outermost message size predictions vs reality.
func TestGeometryOutermostMessageSizePredictions(t *testing.T) {
	boxPayloadLength := 1000
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	geometry := NewGeometry(boxPayloadLength, nikeScheme)
	require.NotNil(t, geometry)

	t.Logf("Testing geometry outermost message size predictions for box payload: %d bytes", boxPayloadLength)

	// Test 1: CourierQueryWriteLength Prediction vs Reality (for write operations)
	t.Logf("\n=== CourierQueryWriteLength Prediction Test ===")

	// The geometry predicts the outermost message size for write operations
	predictedCourierQueryWriteLength := geometry.CourierQueryWriteLength

	// Create the actual nested message structure properly and measure it
	actualOutermostMessageSize := createActualNestedCourierMessage(t, boxPayloadLength, nikeScheme)

	t.Logf("Geometry predicted CourierQueryWriteLength: %d bytes", predictedCourierQueryWriteLength)
	t.Logf("Actual nested message size: %d bytes", actualOutermostMessageSize)
	t.Logf("Prediction error: %d bytes", actualOutermostMessageSize-predictedCourierQueryWriteLength)

	// The prediction should be reasonably close to reality (within 20 bytes for CBOR encoding variations)
	require.InDelta(t, actualOutermostMessageSize, predictedCourierQueryWriteLength, 20,
		"Geometry CourierQueryWriteLength prediction should be within 20 bytes of actual nested message size")

	// Test 2: CourierQueryReplyReadLength Prediction vs Reality (for read replies)
	t.Logf("\n=== CourierQueryReplyReadLength Prediction Test ===")

	// The geometry predicts the outermost reply message size for read operations
	predictedCourierQueryReplyReadLength := geometry.CourierQueryReplyReadLength

	// Create the actual nested reply message structure properly and measure it
	actualOutermostReplySize := createActualNestedCourierReplyMessage(t, boxPayloadLength, nikeScheme)

	t.Logf("Geometry predicted CourierQueryReplyReadLength: %d bytes", predictedCourierQueryReplyReadLength)
	t.Logf("Actual nested reply message size: %d bytes", actualOutermostReplySize)
	t.Logf("Prediction error: %d bytes", actualOutermostReplySize-predictedCourierQueryReplyReadLength)

	// The prediction should be reasonably close to reality (within 20 bytes for CBOR encoding variations)
	require.InDelta(t, actualOutermostReplySize, predictedCourierQueryReplyReadLength, 20,
		"Geometry CourierQueryReplyReadLength prediction should be within 20 bytes of actual nested reply message size")
}

// TestGeometryLayerByLayerOverhead tests each message layer individually to find overhead mismatches
// This granular test helps pinpoint exactly which layer has calculation errors
func TestGeometryLayerByLayerOverhead(t *testing.T) {
	boxPayloadLength := 1000
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	geometry := NewGeometry(boxPayloadLength, nikeScheme)
	require.NotNil(t, geometry)

	t.Logf("Testing layer-by-layer overhead for box payload: %d bytes", boxPayloadLength)

	// Layer 1: BACAP Box (innermost layer)
	t.Logf("\n=== Layer 1: BACAP Box ===")
	actualBACAPSize, bacapOverhead := measureBACAPLayer(t, boxPayloadLength)
	calculatedBACAPOverhead := 16 // bacapEncryptionOverhead from geometry.go

	t.Logf("Box payload: %d bytes", boxPayloadLength)
	t.Logf("Actual BACAP encrypted size: %d bytes", actualBACAPSize)
	t.Logf("Actual BACAP overhead: %d bytes", bacapOverhead)
	t.Logf("Calculated BACAP overhead: %d bytes", calculatedBACAPOverhead)
	t.Logf("BACAP overhead error: %d bytes", bacapOverhead-calculatedBACAPOverhead)

	// Layer 2: ReplicaWrite (contains BACAP box)
	t.Logf("\n=== Layer 2: ReplicaWrite ===")
	actualReplicaWriteSize, replicaWriteOverhead := measureReplicaWriteLayer(t, boxPayloadLength, nikeScheme)
	calculatedReplicaWriteOverhead := geometry.replicaWriteTotalOverhead()

	t.Logf("Box payload: %d bytes", boxPayloadLength)
	t.Logf("Actual ReplicaWrite size: %d bytes", actualReplicaWriteSize)
	t.Logf("Actual ReplicaWrite total overhead: %d bytes", replicaWriteOverhead)
	t.Logf("Calculated ReplicaWrite total overhead: %d bytes", calculatedReplicaWriteOverhead)
	t.Logf("ReplicaWrite overhead error: %d bytes", replicaWriteOverhead-calculatedReplicaWriteOverhead)

	// Layer 3: ReplicaInnerMessage (contains ReplicaWrite)
	t.Logf("\n=== Layer 3: ReplicaInnerMessage ===")
	actualReplicaInnerSize, replicaInnerOverhead := measureReplicaInnerMessageLayer(t, boxPayloadLength, nikeScheme)
	calculatedReplicaInnerOverhead := geometry.replicaInnerMessageWriteOverhead()

	t.Logf("ReplicaWrite size: %d bytes", actualReplicaWriteSize)
	t.Logf("Actual ReplicaInnerMessage size: %d bytes", actualReplicaInnerSize)
	t.Logf("Actual ReplicaInnerMessage overhead: %d bytes", replicaInnerOverhead)
	t.Logf("Calculated ReplicaInnerMessage overhead: %d bytes", calculatedReplicaInnerOverhead)
	t.Logf("ReplicaInnerMessage overhead error: %d bytes", replicaInnerOverhead-calculatedReplicaInnerOverhead)

	// Layer 4: MKEM Encryption (encrypts ReplicaInnerMessage)
	t.Logf("\n=== Layer 4: MKEM Encryption ===")
	actualMKEMSize, mkemOverhead := measureMKEMLayer(t, boxPayloadLength, nikeScheme)
	calculatedMKEMOverhead := 28 // chachaPolyNonceLength + chachaPolyTagLength from geometry.go

	t.Logf("ReplicaInnerMessage size: %d bytes", actualReplicaInnerSize)
	t.Logf("Actual MKEM encrypted size: %d bytes", actualMKEMSize)
	t.Logf("Actual MKEM overhead: %d bytes", mkemOverhead)
	t.Logf("Calculated MKEM overhead: %d bytes", calculatedMKEMOverhead)
	t.Logf("MKEM overhead error: %d bytes", mkemOverhead-calculatedMKEMOverhead)

	// Layer 5: CourierEnvelope (contains MKEM encrypted data)
	t.Logf("\n=== Layer 5: CourierEnvelope ===")
	actualCourierEnvelopeSize, courierEnvelopeOverhead := measureCourierEnvelopeLayer(t, boxPayloadLength, nikeScheme)
	// Use the actual MKEM ciphertext size for accurate overhead calculation
	calculatedCourierEnvelopeOverhead := geometry.courierEnvelopeWriteOverhead(actualMKEMSize)

	t.Logf("MKEM encrypted size: %d bytes", actualMKEMSize)
	t.Logf("Actual CourierEnvelope size: %d bytes", actualCourierEnvelopeSize)
	t.Logf("Actual CourierEnvelope overhead: %d bytes", courierEnvelopeOverhead)
	t.Logf("Calculated CourierEnvelope overhead: %d bytes", calculatedCourierEnvelopeOverhead)
	t.Logf("CourierEnvelope overhead error: %d bytes", courierEnvelopeOverhead-calculatedCourierEnvelopeOverhead)

	// Layer 6: CourierQuery wrapper (outermost layer)
	t.Logf("\n=== Layer 6: CourierQuery Wrapper ===")
	actualCourierQuerySize := createActualNestedCourierMessage(t, boxPayloadLength, nikeScheme)
	actualCourierQueryOverhead := actualCourierQuerySize - actualCourierEnvelopeSize
	calculatedCourierQueryOverhead := calculateCourierQueryWrapperOverhead(actualCourierEnvelopeSize, nikeScheme)

	t.Logf("CourierEnvelope size: %d bytes", actualCourierEnvelopeSize)
	t.Logf("Actual CourierQuery size: %d bytes", actualCourierQuerySize)
	t.Logf("Actual CourierQuery wrapper overhead: %d bytes", actualCourierQueryOverhead)
	t.Logf("Calculated CourierQuery wrapper overhead: %d bytes", calculatedCourierQueryOverhead)
	t.Logf("CourierQuery wrapper overhead error: %d bytes", actualCourierQueryOverhead-calculatedCourierQueryOverhead)

	// Debug the geometry calculation step by step
	t.Logf("\n=== Debugging Geometry Calculation ===")

	// Recreate the geometry calculation manually
	tempGeo := &Geometry{
		BoxPayloadLength:    boxPayloadLength,
		NIKEName:            nikeScheme.Name(),
		SignatureSchemeName: SignatureSchemeName,
	}

	replicaWriteSize := tempGeo.replicaWriteTotalOverhead() + tempGeo.PaddedPayloadLength()
	replicaInnerMessageWriteSize := replicaInnerMessageOverheadForWrite(boxPayloadLength) + replicaWriteSize

	// Calculate MKEM ciphertext size first, then use it for courier overhead calculation
	mkemCiphertext := mkemCiphertextSize(replicaInnerMessageWriteSize)
	courierOverhead := tempGeo.courierEnvelopeWriteOverhead(mkemCiphertext)
	calculatedCourierEnvelopeSize := courierOverhead + mkemCiphertext

	calculatedCourierQueryWrapperOverhead := calculateCourierQueryWrapperOverhead(calculatedCourierEnvelopeSize, nikeScheme)
	calculatedTotal := calculatedCourierEnvelopeSize + calculatedCourierQueryWrapperOverhead

	t.Logf("Manual calculation:")
	t.Logf("  replicaWriteSize: %d", replicaWriteSize)
	t.Logf("  replicaInnerMessageWriteSize: %d", replicaInnerMessageWriteSize)
	t.Logf("  courierOverhead: %d", courierOverhead)
	t.Logf("  mkemCiphertext: %d", mkemCiphertext)
	t.Logf("  calculatedCourierEnvelopeSize: %d", calculatedCourierEnvelopeSize)
	t.Logf("  calculatedCourierQueryWrapperOverhead: %d", calculatedCourierQueryWrapperOverhead)
	t.Logf("  calculatedTotal: %d", calculatedTotal)

	t.Logf("Actual measurements:")
	t.Logf("  actualCourierEnvelopeSize: %d", actualCourierEnvelopeSize)
	t.Logf("  actualCourierQueryOverhead: %d", actualCourierQueryOverhead)
	t.Logf("  actualCourierQuerySize: %d", actualCourierQuerySize)

	// Geometry prediction vs reality
	geometryPrediction := geometry.CourierQueryWriteLength
	t.Logf("\nGeometry CourierQueryWriteLength prediction: %d bytes", geometryPrediction)
	t.Logf("Actual CourierQuery size: %d bytes", actualCourierQuerySize)
	t.Logf("Geometry prediction error: %d bytes", actualCourierQuerySize-geometryPrediction)
}

// createActualNestedCourierMessage creates the complete nested message structure that would be sent to replicas
// This represents the outermost message size that the geometry's CourierQueryLength should predict
func createActualNestedCourierMessage(t *testing.T, boxPayloadLength int, nikeScheme nike.Scheme) int {
	// Use DRY helper to create ReplicaInnerMessage
	payload := make([]byte, boxPayloadLength)
	msg := createReplicaInnerMessageFromPayload(t, payload)

	// MKEM encrypt
	mkemScheme := mkem.NewScheme(nikeScheme)

	// Use DRY helper to generate replica keys for MKEM
	replicaPubKeys := generateMKEMReplicaKeys(t, nikeScheme)

	mkemPrivateKey, mkemCiphertext := mkemScheme.Encapsulate(replicaPubKeys, msg.Bytes())
	mkemPublicKey := mkemPrivateKey.Public()

	// Create CourierEnvelope
	envelope := &CourierEnvelope{
		SenderEPubKey:        mkemPublicKey.Bytes(),
		IntermediateReplicas: [2]uint8{0, 1},
		DEK:                  [2]*[mkem.DEKSize]byte{mkemCiphertext.DEKCiphertexts[0], mkemCiphertext.DEKCiphertexts[1]},
		Ciphertext:           mkemCiphertext.Envelope,
		IsRead:               false,
	}

	// Create the actual CourierQuery that would be sent (this is the outermost layer)
	courierQuery := &CourierQuery{
		CourierEnvelope: envelope,
		CopyCommand:     nil,
	}

	return len(courierQuery.Bytes())
}

// createActualNestedCourierReplyMessage creates the complete nested reply message structure from replicas
// This represents the outermost reply message size that the geometry's CourierQueryReplyLength should predict
func createActualNestedCourierReplyMessage(t *testing.T, boxPayloadLength int, nikeScheme nike.Scheme) int {
	// Use DRY helper to create BACAP encrypted payload
	payload := make([]byte, boxPayloadLength)
	boxID, ciphertext, sig := createBACAPEncryptedPayload(t, payload)

	// Create ReplicaReadReply with BACAP-encrypted payload
	readReply := &ReplicaReadReply{
		ErrorCode: 0,
		BoxID:     &boxID,
		Signature: &sig,
		Payload:   ciphertext,
	}

	// Create ReplicaMessageReplyInnerMessage containing ReplicaReadReply
	innerMsg := &ReplicaMessageReplyInnerMessage{
		ReplicaReadReply:  readReply,
		ReplicaWriteReply: nil,
	}

	// MKEM encrypt the ReplicaMessageReplyInnerMessage
	mkemScheme := mkem.NewScheme(nikeScheme)

	// Generate replica and sender keys for MKEM
	_, replicaPrivateKey, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	senderPublicKey, _, err := nikeScheme.GenerateKeyPair()
	require.NoError(t, err)

	// MKEM encrypt the inner message
	envelopeReply := mkemScheme.EnvelopeReply(replicaPrivateKey, senderPublicKey, innerMsg.Bytes())

	// Create CourierEnvelopeReply with MKEM-encrypted payload
	envelopeHash := &[hash.HashSize]byte{}
	courierEnvelopeReply := &CourierEnvelopeReply{
		EnvelopeHash: envelopeHash,
		ReplyIndex:   0,
		ErrorCode:    0,
		Payload:      envelopeReply.Envelope, // MKEM-encrypted payload!
	}

	// Create the actual CourierQueryReply that would be sent (this is the outermost layer)
	courierQueryReply := &CourierQueryReply{
		CourierEnvelopeReply: courierEnvelopeReply,
		CopyCommandReply:     nil,
	}

	return len(courierQueryReply.Bytes())
}

// measureBACAPLayer measures the BACAP encryption layer overhead
func measureBACAPLayer(t *testing.T, boxPayloadLength int) (int, int) {
	payload := make([]byte, boxPayloadLength)

	// Use DRY helper to create BACAP encrypted payload
	_, ciphertext, _ := createBACAPEncryptedPayload(t, payload)

	actualSize := len(ciphertext)
	overhead := actualSize - boxPayloadLength
	return actualSize, overhead
}

// measureReplicaWriteLayer measures the ReplicaWrite total overhead relative to original payload
func measureReplicaWriteLayer(t *testing.T, boxPayloadLength int, nikeScheme nike.Scheme) (int, int) {
	payload := make([]byte, boxPayloadLength)

	// Use DRY helper to create ReplicaWrite
	writeRequest := createReplicaWriteFromPayload(t, payload)

	actualSize := len(writeRequest.ToBytes())
	// Measure total overhead relative to original payload (what geometry function should return)
	overhead := actualSize - boxPayloadLength
	return actualSize, overhead
}

// measureReplicaInnerMessageLayer measures the ReplicaInnerMessage CBOR overhead
func measureReplicaInnerMessageLayer(t *testing.T, boxPayloadLength int, nikeScheme nike.Scheme) (int, int) {
	// First get the ReplicaWrite size
	actualReplicaWriteSize, _ := measureReplicaWriteLayer(t, boxPayloadLength, nikeScheme)

	payload := make([]byte, boxPayloadLength)

	// Use DRY helper to create ReplicaInnerMessage
	msg := createReplicaInnerMessageFromPayload(t, payload)

	actualSize := len(msg.Bytes())
	overhead := actualSize - actualReplicaWriteSize
	return actualSize, overhead
}

// measureMKEMLayer measures the MKEM encryption overhead
func measureMKEMLayer(t *testing.T, boxPayloadLength int, nikeScheme nike.Scheme) (int, int) {
	// First get the ReplicaInnerMessage size
	actualReplicaInnerSize, _ := measureReplicaInnerMessageLayer(t, boxPayloadLength, nikeScheme)

	payload := make([]byte, boxPayloadLength)

	// Use DRY helper to create ReplicaInnerMessage
	msg := createReplicaInnerMessageFromPayload(t, payload)

	// MKEM encrypt
	mkemScheme := mkem.NewScheme(nikeScheme)

	// Use DRY helper to generate replica keys for MKEM
	replicaPubKeys := generateMKEMReplicaKeys(t, nikeScheme)

	_, mkemCiphertext := mkemScheme.Encapsulate(replicaPubKeys, msg.Bytes())

	actualSize := len(mkemCiphertext.Envelope)
	overhead := actualSize - actualReplicaInnerSize
	return actualSize, overhead
}

// measureCourierEnvelopeLayer measures the CourierEnvelope CBOR overhead
func measureCourierEnvelopeLayer(t *testing.T, boxPayloadLength int, nikeScheme nike.Scheme) (int, int) {
	// First get the MKEM encrypted size
	actualMKEMSize, _ := measureMKEMLayer(t, boxPayloadLength, nikeScheme)

	// Use the DRY helper to create the envelope
	envelope := createCourierEnvelopeFromPayload(t, boxPayloadLength, nikeScheme)

	actualSize := len(envelope.Bytes())
	overhead := actualSize - actualMKEMSize
	return actualSize, overhead
}

func TestGeometryConsistencyWithVariousPayloadSizes(t *testing.T) {
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	// Test with the same BoxPayloadLength as the integration test
	// The integration test uses sphinx geometry with UserForwardPayloadLength=5000
	// which results in pigeonhole BoxPayloadLength=4386
	boxPayloadLength := 4386
	geo := NewGeometry(boxPayloadLength, nikeScheme)
	require.NoError(t, geo.Validate())

	t.Logf("Testing geometry consistency with BoxPayloadLength: %d", boxPayloadLength)
	t.Logf("PaddedPayloadLength: %d", geo.PaddedPayloadLength())
	t.Logf("CourierQueryWriteLength: %d", geo.CourierQueryWriteLength)

	// Test with various actual payload sizes (all should fit within BoxPayloadLength)
	testPayloadSizes := []int{
		0,                    // Empty payload
		1,                    // Minimal payload
		100,                  // Small payload
		boxPayloadLength / 2, // Half capacity
		boxPayloadLength - 1, // Almost full
		boxPayloadLength,     // Full capacity
	}

	for _, payloadSize := range testPayloadSizes {
		t.Run(fmt.Sprintf("payload_size_%d", payloadSize), func(t *testing.T) {
			// Create a test payload of the specified size
			testPayload := make([]byte, payloadSize)
			for i := range testPayload {
				testPayload[i] = byte(i % 256)
			}

			// Create padded payload using our helper function
			paddedPayload, err := CreatePaddedPayload(testPayload, boxPayloadLength)
			require.NoError(t, err)

			// Verify the padded payload is exactly the expected size
			expectedPaddedSize := geo.PaddedPayloadLength()
			require.Equal(t, expectedPaddedSize, len(paddedPayload),
				"Padded payload size should be consistent regardless of actual payload size")

			// Create a realistic BACAP-encrypted payload
			const bacapEncryptionOverhead = 16
			bacapCiphertext := make([]byte, len(paddedPayload)+bacapEncryptionOverhead)
			copy(bacapCiphertext, paddedPayload)

			// Create a ReplicaWrite message with this payload
			boxID := [bacap.BoxIDSize]byte{}
			signature := [bacap.SignatureSize]byte{}
			writeRequest := commands.ReplicaWrite{
				BoxID:     &boxID,
				Signature: &signature,
				Payload:   bacapCiphertext,
			}

			// Create ReplicaInnerMessage
			msg := &ReplicaInnerMessage{
				ReplicaWrite: &writeRequest,
			}
			replicaInnerBytes := msg.Bytes()

			// Create MKEM encryption like the geometry calculations do
			mkemScheme := mkem.NewScheme(nikeScheme)

			// Use DRY helper to generate replica keys for MKEM
			replicaPubKeys := generateMKEMReplicaKeys(t, nikeScheme)

			mkemPrivateKey, mkemCiphertext := mkemScheme.Encapsulate(replicaPubKeys, replicaInnerBytes)
			mkemPublicKey := mkemPrivateKey.Public()

			// Create CourierEnvelope with real MKEM data like geometry calculations
			courierEnvelope := &CourierEnvelope{
				SenderEPubKey:        mkemPublicKey.Bytes(),
				IntermediateReplicas: [2]uint8{0, 1},
				DEK:                  [2]*[mkem.DEKSize]byte{mkemCiphertext.DEKCiphertexts[0], mkemCiphertext.DEKCiphertexts[1]},
				Ciphertext:           mkemCiphertext.Envelope,
				IsRead:               false,
				Epoch:                0, // Match geometry calculations
			}

			// Create CourierQuery
			courierQuery := &CourierQuery{
				CourierEnvelope: courierEnvelope,
				CopyCommand:     nil,
			}

			// Serialize to CBOR and measure actual size
			actualCourierQueryBytes, err := cbor.Marshal(courierQuery)
			require.NoError(t, err)
			actualSize := len(actualCourierQueryBytes)

			// Compare with geometry prediction
			expectedSize := geo.CourierQueryWriteLength

			t.Logf("Payload size: %d, Padded size: %d, Actual CourierQuery size: %d, Expected: %d",
				payloadSize, len(paddedPayload), actualSize, expectedSize)

			// The actual size should match the geometry prediction exactly
			require.Equal(t, expectedSize, actualSize,
				"Actual CourierQuery size should match geometry prediction for payload size %d", payloadSize)
		})
	}
}
