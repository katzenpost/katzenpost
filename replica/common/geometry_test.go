// SPDX-FileCopyrightText: Copyright (C) 2024  David Anthony Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"crypto/rand"
	"testing"

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
	testContext     = "test-context"
	ctidh1024X25519 = "CTIDH1024-X25519"
)

func TestReplicaWriteOverhead(t *testing.T) {
	payload := make([]byte, 1000)

	// Create BACAP StatefulWriter to encrypt the payload
	owner, err := bacap.NewBoxOwnerCap(rand.Reader)
	require.NoError(t, err)

	ctx := []byte(testContext)
	statefulWriter, err := bacap.NewStatefulWriter(owner, ctx)
	require.NoError(t, err)

	// Use BACAP to encrypt the payload (this adds AES-GCM-SIV overhead)
	boxID, bacapCiphertext, sigraw, err := statefulWriter.EncryptNext(payload)
	require.NoError(t, err)

	sig := [bacap.SignatureSize]byte{}
	copy(sig[:], sigraw)

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

func TestCourierEnvelopeOverhead(t *testing.T) {
	// Create a CourierEnvelope with fixed payload size
	payload := make([]byte, 1000)

	// Create NIKE scheme for envelope keys
	scheme := schemes.ByName(ctidh1024X25519)
	require.NotNil(t, scheme)

	// Generate ephemeral key pair
	ephemeralPub, _, err := scheme.GenerateKeyPair()
	require.NoError(t, err)
	ephemeralPubBytes := ephemeralPub.Bytes()

	envelope := &CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1},
		DEK:                  [2]*[mkem.DEKSize]byte{{}, {}},
		ReplyIndex:           0,
		Epoch:                12345,
		SenderEPubKey:        ephemeralPubBytes,
		IsRead:               false,
		Ciphertext:           payload,
	}

	envelopeBytes := envelope.Bytes()
	overhead := len(envelopeBytes) - len(payload)

	nikeScheme := schemes.ByName(ctidh1024X25519)
	require.NotNil(t, nikeScheme)
	geo := NewGeometry(len(payload), nikeScheme)
	overhead2 := geo.courierEnvelopeOverhead()

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

	// Test ReplicaWrite case - use BACAP encryption like the main test
	owner, err := bacap.NewBoxOwnerCap(rand.Reader)
	require.NoError(t, err)

	ctx := []byte(testContext)
	statefulWriter, err := bacap.NewStatefulWriter(owner, ctx)
	require.NoError(t, err)

	// Use BACAP to encrypt the payload
	boxID, bacapCiphertext, sigraw, err := statefulWriter.EncryptNext(payload)
	require.NoError(t, err)

	sig := [bacap.SignatureSize]byte{}
	copy(sig[:], sigraw)

	writeMsg := &ReplicaInnerMessage{
		ReplicaRead: nil,
		ReplicaWrite: &commands.ReplicaWrite{
			Cmds:      nil, // no padding
			BoxID:     &boxID,
			Signature: &sig,
			Payload:   bacapCiphertext, // Use encrypted payload
		},
	}
	writeMsgBytes := writeMsg.Bytes()
	writeOverhead := len(writeMsgBytes) - len(payload) // Compare against original payload size

	// Debug: let's see what the individual components calculate to
	replicaReadOverhead := geo.replicaReadOverhead()
	replicaWriteOverhead := geo.replicaWriteOverhead()

	t.Logf("readOverhead (actual): %d", readOverhead)
	t.Logf("writeOverhead (actual): %d", writeOverhead)
	t.Logf("replicaReadOverhead (calculated): %d", replicaReadOverhead)
	t.Logf("replicaWriteOverhead (calculated): %d", replicaWriteOverhead)

	// The calculated overhead should accommodate both cases
	calculatedOverhead := geo.replicaInnerMessageOverhead()
	t.Logf("calculatedOverhead: %d", calculatedOverhead)

	// The calculated overhead should be at least as large as both actual overheads
	require.GreaterOrEqual(t, calculatedOverhead, readOverhead)
	require.GreaterOrEqual(t, calculatedOverhead, writeOverhead)
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
	t.Logf("  Calculated CourierQueryLength: %d", pigeonholeGeometry.CourierQueryLength)
	t.Logf("  Actual CourierEnvelopeLength: %d", actualCourierEnvelopeSize)
	t.Logf("  Calculated CourierQueryReplyLength: %d", pigeonholeGeometry.CourierQueryReplyLength)
	t.Logf("  Actual CourierEnvelopeReplyLength: %d", actualCourierEnvelopeReplySize)

	// The calculated sizes should be very close to actual REAL message sizes
	require.InDelta(t, actualCourierEnvelopeSize, pigeonholeGeometry.CourierQueryLength, 35,
		"CourierQuery geometry calculation should be within 35 bytes of actual CourierEnvelope (includes wrapper overhead)")
	require.InDelta(t, actualCourierEnvelopeReplySize, pigeonholeGeometry.CourierQueryReplyLength, 100,
		"CourierQueryReply geometry calculation should be within 100 bytes of actual CourierEnvelopeReply (includes wrapper overhead and MKEM encryption)")
}

// TestGeometryUseCase2 tests Use Case 2: specify precomputed PigeonholeGeometry and derive SphinxGeometry
func TestGeometryUseCase2(t *testing.T) {
	// Create a precomputed pigeonhole geometry
	boxPayloadLength := 2000
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	precomputedPigeonholeGeometry := &Geometry{
		CourierQueryLength:      boxPayloadLength + 150, // Some overhead
		CourierQueryReplyLength: 82,                     // Some reply overhead
		NIKEName:                nikeScheme.Name(),
		SignatureSchemeName:     SignatureSchemeName,
		BoxPayloadLength:        boxPayloadLength,
	}

	nrHops := 7
	sphinxGeometry := GeometryFromPigeonholeGeometry(precomputedPigeonholeGeometry, nrHops)

	// Validate sphinx geometry
	require.NotNil(t, sphinxGeometry)
	require.Equal(t, nikeScheme.Name(), sphinxGeometry.NIKEName)
	require.Equal(t, nrHops, sphinxGeometry.NrHops)
	require.Greater(t, sphinxGeometry.PacketLength, 0)
	require.GreaterOrEqual(t, sphinxGeometry.UserForwardPayloadLength, precomputedPigeonholeGeometry.CourierQueryLength)

	// Test that sphinx geometry validates
	require.NoError(t, sphinxGeometry.Validate())

	t.Logf("Use Case 2 Results:")
	t.Logf("  Precomputed CourierQueryLength: %d", precomputedPigeonholeGeometry.CourierQueryLength)
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
	userForwardPayloadLength := 3200 // Increased to accommodate CourierQuery overhead
	nrHops := 5

	precomputedSphinxGeometry := geo.GeometryFromUserForwardPayloadLength(nikeScheme, userForwardPayloadLength, true, nrHops)
	require.NotNil(t, precomputedSphinxGeometry)

	pigeonholeNikeScheme := schemes.ByName(ctidh1024X25519)
	require.NotNil(t, pigeonholeNikeScheme)
	pigeonholeGeometry := GeometryFromSphinxGeometry(precomputedSphinxGeometry, pigeonholeNikeScheme)

	// Validate pigeonhole geometry
	require.NotNil(t, pigeonholeGeometry)
	// Pigeonhole uses the specified NIKE scheme, independent of Sphinx NIKE scheme
	require.Equal(t, pigeonholeNikeScheme.Name(), pigeonholeGeometry.NIKEName)
	require.Equal(t, SignatureSchemeName, pigeonholeGeometry.SignatureSchemeName)
	require.Greater(t, pigeonholeGeometry.BoxPayloadLength, 0)
	require.Greater(t, pigeonholeGeometry.CourierQueryLength, pigeonholeGeometry.BoxPayloadLength)
	require.Greater(t, pigeonholeGeometry.CourierQueryReplyLength, 0)

	// Ensure the pigeonhole messages fit within the sphinx constraint
	require.LessOrEqual(t, pigeonholeGeometry.CourierQueryLength, precomputedSphinxGeometry.UserForwardPayloadLength)

	// Test that pigeonhole geometry validates
	require.NoError(t, pigeonholeGeometry.Validate())

	t.Logf("Use Case 3 Results:")
	t.Logf("  Sphinx UserForwardPayloadLength constraint: %d", precomputedSphinxGeometry.UserForwardPayloadLength)
	t.Logf("  Derived BoxPayloadLength: %d", pigeonholeGeometry.BoxPayloadLength)
	t.Logf("  Derived CourierQueryLength: %d", pigeonholeGeometry.CourierQueryLength)
	t.Logf("  Derived CourierQueryReplyLength: %d", pigeonholeGeometry.CourierQueryReplyLength)
}

// composeActualCourierEnvelope creates the REAL CourierEnvelope using the exact same approach
// as TestCourierReplicaIntegration in aliceComposesNextMessage()
func composeActualCourierEnvelope(t *testing.T, boxPayloadLength int, nikeScheme nike.Scheme) int {
	// Step 1: Create BACAP encrypted payload (exactly like integration test)
	payload := make([]byte, boxPayloadLength)
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

	// Step 2: Create ReplicaWrite (exactly like integration test)
	writeRequest := commands.ReplicaWrite{
		BoxID:     &boxID,
		Signature: &sig,
		Payload:   ciphertext,
	}

	// Step 3: Create ReplicaInnerMessage (exactly like integration test)
	msg := &ReplicaInnerMessage{
		ReplicaWrite: &writeRequest,
	}

	// Step 4: MKEM encrypt (exactly like integration test)
	mkemScheme := mkem.NewScheme(nikeScheme)

	// Generate replica keys for MKEM
	replicaPubKeys := make([]nike.PublicKey, 2)
	for i := 0; i < 2; i++ {
		pub, _, err := nikeScheme.GenerateKeyPair()
		require.NoError(t, err)
		replicaPubKeys[i] = pub
	}

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

	// Return the actual serialized size of the REAL CourierEnvelope
	return len(envelope.Bytes())
}

// composeActualCourierEnvelopeReply creates the REAL CourierEnvelopeReply using the same approach
// as replica handlers.go (lines 124-136) with MKEM encryption
func composeActualCourierEnvelopeReply(t *testing.T, boxPayloadLength int, nikeScheme nike.Scheme) int {
	// Step 1: Create BACAP encrypted payload (what would be returned in a read)
	payload := make([]byte, boxPayloadLength)
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

	// Return the actual serialized size of the REAL CourierEnvelopeReply
	return len(reply.Bytes())
}
