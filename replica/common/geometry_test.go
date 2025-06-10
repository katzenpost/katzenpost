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
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func TestReplicaWriteOverhead(t *testing.T) {
	payload := make([]byte, 1000)

	// Create BACAP StatefulWriter to encrypt the payload
	owner, err := bacap.NewBoxOwnerCap(rand.Reader)
	require.NoError(t, err)

	ctx := []byte("test-context")
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

	geo := NewGeometry(len(payload))
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

	geo := NewGeometry(1000) // payload size doesn't matter for read overhead
	overhead2 := geo.replicaReadOverhead()

	t.Logf("readCmdBytes overhead: %d", overhead)
	t.Logf("geo.replicaReadOverhead: %d", overhead2)

	require.Equal(t, overhead, overhead2)
}

func TestCourierEnvelopeOverhead(t *testing.T) {
	// Create a CourierEnvelope with fixed payload size
	payload := make([]byte, 1000)

	// Create NIKE scheme for envelope keys
	scheme := schemes.ByName("CTIDH1024-X25519")
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

	geo := NewGeometry(len(payload))
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

	geo := NewGeometry(len(payload))
	overhead2 := geo.courierEnvelopeReplyOverhead()

	t.Logf("geo.courierEnvelopeReplyOverhead: %d", overhead2)

	require.Equal(t, overhead, overhead2)
}

func TestReplicaInnerMessageOverhead(t *testing.T) {
	payload := make([]byte, 1000)
	geo := NewGeometry(len(payload))

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

	ctx := []byte("test-context")
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
	require.Greater(t, pigeonholeGeometry.CourierEnvelopeLength, boxPayloadLength)
	require.Greater(t, pigeonholeGeometry.CourierEnvelopeReplyLength, 0)

	// Test that pigeonhole geometry validates
	require.NoError(t, pigeonholeGeometry.Validate())

	t.Logf("Use Case 1 Results:")
	t.Logf("  BoxPayloadLength: %d", boxPayloadLength)
	t.Logf("  CourierEnvelopeLength: %d", pigeonholeGeometry.CourierEnvelopeLength)
	t.Logf("  CourierEnvelopeReplyLength: %d", pigeonholeGeometry.CourierEnvelopeReplyLength)
}

// TestGeometryUseCase2 tests Use Case 2: specify precomputed PigeonholeGeometry and derive SphinxGeometry
func TestGeometryUseCase2(t *testing.T) {
	// Create a precomputed pigeonhole geometry
	boxPayloadLength := 2000
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	precomputedPigeonholeGeometry := &Geometry{
		CourierEnvelopeLength:      boxPayloadLength + 150, // Some overhead
		CourierEnvelopeReplyLength: 82,                     // Some reply overhead
		NIKEName:                   nikeScheme.Name(),
		SignatureSchemeName:        SignatureSchemeName,
		BoxPayloadLength:           boxPayloadLength,
	}

	nrHops := 7
	sphinxGeometry := GeometryFromPigeonholeGeometry(precomputedPigeonholeGeometry, nrHops)

	// Validate sphinx geometry
	require.NotNil(t, sphinxGeometry)
	require.Equal(t, nikeScheme.Name(), sphinxGeometry.NIKEName)
	require.Equal(t, nrHops, sphinxGeometry.NrHops)
	require.Greater(t, sphinxGeometry.PacketLength, 0)
	require.GreaterOrEqual(t, sphinxGeometry.UserForwardPayloadLength, precomputedPigeonholeGeometry.CourierEnvelopeLength)

	// Test that sphinx geometry validates
	require.NoError(t, sphinxGeometry.Validate())

	t.Logf("Use Case 2 Results:")
	t.Logf("  Precomputed CourierEnvelopeLength: %d", precomputedPigeonholeGeometry.CourierEnvelopeLength)
	t.Logf("  Precomputed BoxPayloadLength: %d", precomputedPigeonholeGeometry.BoxPayloadLength)
	t.Logf("  Derived Sphinx UserForwardPayloadLength: %d", sphinxGeometry.UserForwardPayloadLength)
	t.Logf("  Derived Sphinx PacketLength: %d", sphinxGeometry.PacketLength)
}

// TestGeometryUseCase3 tests Use Case 3: specify precomputed SphinxGeometry and derive PigeonholeGeometry
func TestGeometryUseCase3(t *testing.T) {
	// Create a precomputed sphinx geometry with size constraints
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)
	userForwardPayloadLength := 3000
	nrHops := 5

	precomputedSphinxGeometry := geo.GeometryFromUserForwardPayloadLength(nikeScheme, userForwardPayloadLength, true, nrHops)
	require.NotNil(t, precomputedSphinxGeometry)

	pigeonholeGeometry := GeometryFromSphinxGeometry(precomputedSphinxGeometry)

	// Validate pigeonhole geometry
	require.NotNil(t, pigeonholeGeometry)
	// Pigeonhole uses its own NIKE scheme, NOT the Sphinx NIKE scheme
	require.Equal(t, NikeScheme.Name(), pigeonholeGeometry.NIKEName)
	require.Equal(t, SignatureSchemeName, pigeonholeGeometry.SignatureSchemeName)
	require.Greater(t, pigeonholeGeometry.BoxPayloadLength, 0)
	require.Greater(t, pigeonholeGeometry.CourierEnvelopeLength, pigeonholeGeometry.BoxPayloadLength)
	require.Greater(t, pigeonholeGeometry.CourierEnvelopeReplyLength, 0)

	// Ensure the pigeonhole messages fit within the sphinx constraint
	require.LessOrEqual(t, pigeonholeGeometry.CourierEnvelopeLength, precomputedSphinxGeometry.UserForwardPayloadLength)

	// Test that pigeonhole geometry validates
	require.NoError(t, pigeonholeGeometry.Validate())

	t.Logf("Use Case 3 Results:")
	t.Logf("  Sphinx UserForwardPayloadLength constraint: %d", precomputedSphinxGeometry.UserForwardPayloadLength)
	t.Logf("  Derived BoxPayloadLength: %d", pigeonholeGeometry.BoxPayloadLength)
	t.Logf("  Derived CourierEnvelopeLength: %d", pigeonholeGeometry.CourierEnvelopeLength)
	t.Logf("  Derived CourierEnvelopeReplyLength: %d", pigeonholeGeometry.CourierEnvelopeReplyLength)
}

// TestGeometryRoundTrip tests that all 3 use cases are compatible and work together
func TestGeometryRoundTrip(t *testing.T) {
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)
	nrHops := 5

	// Start with Use Case 1: BoxPayloadLength -> PigeonholeGeometry
	originalBoxPayloadLength := 1500
	pigeonhole1 := GeometryFromBoxPayloadLength(originalBoxPayloadLength, nikeScheme)

	// Then use Use Case 2 to get SphinxGeometry
	sphinx1 := GeometryFromPigeonholeGeometry(pigeonhole1, nrHops)

	t.Logf("Round Trip Test:")
	t.Logf("Step 1 - Use Case 1 (BoxPayloadLength=%d):", originalBoxPayloadLength)
	t.Logf("  -> PigeonholeGeometry: CourierEnvelopeLength=%d, BoxPayloadLength=%d",
		pigeonhole1.CourierEnvelopeLength, pigeonhole1.BoxPayloadLength)
	t.Logf("Step 1b - Use Case 2 (from PigeonholeGeometry):")
	t.Logf("  -> SphinxGeometry: UserForwardPayloadLength=%d, PacketLength=%d",
		sphinx1.UserForwardPayloadLength, sphinx1.PacketLength)

	// Use Case 2: PigeonholeGeometry -> SphinxGeometry
	sphinx2 := GeometryFromPigeonholeGeometry(pigeonhole1, nrHops)

	t.Logf("Step 2 - Use Case 2 (from PigeonholeGeometry):")
	t.Logf("  -> SphinxGeometry: UserForwardPayloadLength=%d, PacketLength=%d",
		sphinx2.UserForwardPayloadLength, sphinx2.PacketLength)

	// Use Case 3: SphinxGeometry -> PigeonholeGeometry
	pigeonhole3 := GeometryFromSphinxGeometry(sphinx1)

	t.Logf("Step 3 - Use Case 3 (from SphinxGeometry):")
	t.Logf("  -> PigeonholeGeometry: CourierEnvelopeLength=%d, BoxPayloadLength=%d",
		pigeonhole3.CourierEnvelopeLength, pigeonhole3.BoxPayloadLength)

	// Validate all geometries
	require.NoError(t, pigeonhole1.Validate())
	require.NoError(t, sphinx1.Validate())
	require.NoError(t, sphinx2.Validate())
	require.NoError(t, pigeonhole3.Validate())

	// Test consistency: sphinx geometries should be compatible
	require.Equal(t, sphinx1.NIKEName, sphinx2.NIKEName)
	require.Equal(t, sphinx1.NrHops, sphinx2.NrHops)

	// Sphinx and Pigeonhole NIKE schemes are independent
	require.Equal(t, nikeScheme.Name(), sphinx1.NIKEName)  // Sphinx uses x25519
	require.Equal(t, NikeScheme.Name(), pigeonhole3.NIKEName)  // Pigeonhole uses CTIDH1024-X25519

	// Test that pigeonhole geometries use their respective NIKE schemes correctly
	// pigeonhole1 was created with x25519 (from GeometryFromBoxPayloadLength)
	require.Equal(t, nikeScheme.Name(), pigeonhole1.NIKEName)
	// pigeonhole3 was created with default CTIDH1024-X25519 (from GeometryFromSphinxGeometry)
	require.Equal(t, NikeScheme.Name(), pigeonhole3.NIKEName)
	// Both use the same signature scheme
	require.Equal(t, pigeonhole1.SignatureSchemeName, pigeonhole3.SignatureSchemeName)

	// Test that the derived BoxPayloadLength from Use Case 3 is reasonable
	// (it will be different due to different NIKE schemes having different overhead)
	require.Greater(t, pigeonhole3.BoxPayloadLength, 0)

	// The final BoxPayloadLength may be different from the original because:
	// 1. Use Case 1 uses x25519 for Sphinx geometry creation
	// 2. Use Case 3 uses CTIDH1024-X25519 for Pigeonhole geometry creation
	// 3. Different NIKE schemes have different overhead calculations

	// Test that all messages fit within their respective constraints
	require.LessOrEqual(t, pigeonhole1.CourierEnvelopeLength, sphinx1.UserForwardPayloadLength)
	require.LessOrEqual(t, pigeonhole1.CourierEnvelopeLength, sphinx2.UserForwardPayloadLength)
	require.LessOrEqual(t, pigeonhole3.CourierEnvelopeLength, sphinx1.UserForwardPayloadLength)

	t.Logf("Round trip test completed successfully!")
	t.Logf("Original BoxPayloadLength: %d, Final BoxPayloadLength: %d",
		originalBoxPayloadLength, pigeonhole3.BoxPayloadLength)
	t.Logf("Note: Different BoxPayloadLength is expected due to independent NIKE schemes")
}

// TestGeometryFactoryDemo demonstrates practical usage of the geometry factory
func TestGeometryFactoryDemo(t *testing.T) {
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	t.Logf("=== Pigeonhole Geometry Factory Demo ===")

	// Scenario 1: Application developer knows they need 2KB payload
	t.Logf("\nScenario 1: Application needs 2KB payload (Use Case 1)")
	pigeonhole1 := GeometryFromBoxPayloadLength(2048, nikeScheme)
	t.Logf("  Input: BoxPayloadLength = 2048 bytes")
	t.Logf("  Output: CourierEnvelopeLength = %d bytes", pigeonhole1.CourierEnvelopeLength)
	t.Logf("  Envelope overhead: %.2f%%", float64(pigeonhole1.CourierEnvelopeLength-2048)/float64(2048)*100)

	// Scenario 2: System administrator has predefined pigeonhole requirements
	t.Logf("\nScenario 2: Predefined pigeonhole geometry")
	predefinedPigeonhole := &Geometry{
		CourierEnvelopeLength:      4000,
		CourierEnvelopeReplyLength: 82,
		NIKEName:                   "x25519",
		SignatureSchemeName:        "Ed25519",
		BoxPayloadLength:           3755, // 4000 - 245 overhead
	}
	sphinx2 := GeometryFromPigeonholeGeometry(predefinedPigeonhole, 7)
	t.Logf("  Input: CourierEnvelopeLength = %d bytes", predefinedPigeonhole.CourierEnvelopeLength)
	t.Logf("  Output: Sphinx PacketLength = %d bytes", sphinx2.PacketLength)
	t.Logf("  Mixnet hops: %d", sphinx2.NrHops)

	// Scenario 3: Network operator has Sphinx packet size constraints
	t.Logf("\nScenario 3: Sphinx packet size constraint")
	constraintSphinx := geo.GeometryFromUserForwardPayloadLength(nikeScheme, 5000, true, 10)
	pigeonhole3 := GeometryFromSphinxGeometry(constraintSphinx)
	t.Logf("  Input: Sphinx UserForwardPayloadLength = %d bytes", constraintSphinx.UserForwardPayloadLength)
	t.Logf("  Input: Sphinx PacketLength = %d bytes", constraintSphinx.PacketLength)
	t.Logf("  Output: BoxPayloadLength = %d bytes", pigeonhole3.BoxPayloadLength)
	t.Logf("  Efficiency: %.2f%% payload utilization",
		float64(pigeonhole3.BoxPayloadLength)/float64(constraintSphinx.UserForwardPayloadLength)*100)

	// All geometries should validate
	require.NoError(t, pigeonhole1.Validate())
	require.NoError(t, sphinx2.Validate())
	require.NoError(t, constraintSphinx.Validate())
	require.NoError(t, pigeonhole3.Validate())

	t.Logf("\n=== Demo completed successfully! ===")
}
