// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// TestCourierWriteSizeValidation tests that the courier rejects writes with incorrect ciphertext sizes
func NoTestCourierWriteSizeValidation(t *testing.T) {
	// Create geometry
	boxPayloadLength := 1000
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	geometry := replicaCommon.GeometryFromBoxPayloadLength(boxPayloadLength, nikeScheme)
	require.NotNil(t, geometry)

	// Create a mock courier (we only need the geometry validation part)
	logger := logging.MustGetLogger("test")
	courier := &Courier{
		pigeonholeGeo: geometry,
		log:           logger,
	}

	// Test 1: Create a properly sized write envelope (should pass validation)
	t.Run("ValidWriteSize", func(t *testing.T) {
		envelope := createTestWriteEnvelope(t, geometry, boxPayloadLength, nikeScheme)
		err := validateCourierEnvelopeSize(courier, envelope)
		require.NoError(t, err, "Properly sized write should pass validation")
	})

	// Test 2: Create an undersized write envelope (should fail validation)
	t.Run("UndersizedWrite", func(t *testing.T) {
		envelope := createTestWriteEnvelope(t, geometry, boxPayloadLength-100, nikeScheme)
		err := validateCourierEnvelopeSize(courier, envelope)
		require.Error(t, err, "Undersized write should fail validation")
		require.Equal(t, errGeometryViolation, err)
	})

	// Test 3: Create an oversized write envelope (should fail validation)
	t.Run("OversizedWrite", func(t *testing.T) {
		envelope := createTestWriteEnvelope(t, geometry, boxPayloadLength+100, nikeScheme)
		err := validateCourierEnvelopeSize(courier, envelope)
		require.Error(t, err, "Oversized write should fail validation")
		require.Equal(t, errGeometryViolation, err)
	})

	// Test 4: Read operations should not be affected by ciphertext size validation
	t.Run("ReadNotAffected", func(t *testing.T) {
		envelope := createTestReadEnvelope(t, geometry, nikeScheme)
		err := validateCourierEnvelopeSize(courier, envelope)
		require.NoError(t, err, "Read operations should not be affected by write size validation")
	})
}

// createTestWriteEnvelope creates a CourierEnvelope for write operations with the specified payload size
func createTestWriteEnvelope(t *testing.T, geometry *replicaCommon.Geometry, payloadSize int, nikeScheme nike.Scheme) *replicaCommon.CourierEnvelope {
	// Create BACAP encrypted payload
	payload := make([]byte, payloadSize)
	owner, err := bacap.NewBoxOwnerCap(rand.Reader)
	require.NoError(t, err)

	statefulWriter, err := bacap.NewStatefulWriter(owner, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)

	boxID, ciphertext, sigraw, err := statefulWriter.EncryptNext(payload)
	require.NoError(t, err)

	sig := [bacap.SignatureSize]byte{}
	copy(sig[:], sigraw)

	// Create ReplicaWrite
	writeRequest := commands.ReplicaWrite{
		BoxID:     &boxID,
		Signature: &sig,
		Payload:   ciphertext,
	}

	// Create ReplicaInnerMessage
	msg := &replicaCommon.ReplicaInnerMessage{
		ReplicaWrite: &writeRequest,
	}

	// Create MKEM encryption
	mkemScheme := mkem.NewScheme(nikeScheme)
	replicaPubKeys := make([]nike.PublicKey, 2)
	for i := 0; i < 2; i++ {
		pub, _, err := nikeScheme.GenerateKeyPair()
		require.NoError(t, err)
		replicaPubKeys[i] = pub
	}

	mkemPrivateKey, mkemCiphertext := mkemScheme.Encapsulate(replicaPubKeys, msg.Bytes())
	mkemPublicKey := mkemPrivateKey.Public()

	// Create CourierEnvelope
	return &replicaCommon.CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1},
		DEK:                  [2]*[mkem.DEKSize]byte{mkemCiphertext.DEKCiphertexts[0], mkemCiphertext.DEKCiphertexts[1]},
		SenderEPubKey:        mkemPublicKey.Bytes(),
		Ciphertext:           mkemCiphertext.Envelope,
		IsRead:               false,
	}
}

// createTestReadEnvelope creates a CourierEnvelope for read operations
func createTestReadEnvelope(t *testing.T, geometry *replicaCommon.Geometry, nikeScheme nike.Scheme) *replicaCommon.CourierEnvelope {
	// Create ReplicaRead
	boxID := [bacap.BoxIDSize]byte{}
	readRequest := replicaCommon.ReplicaRead{
		BoxID: &boxID,
	}

	// Create ReplicaInnerMessage
	msg := &replicaCommon.ReplicaInnerMessage{
		ReplicaRead: &readRequest,
	}

	// Create MKEM encryption
	mkemScheme := mkem.NewScheme(nikeScheme)
	replicaPubKeys := make([]nike.PublicKey, 2)
	for i := 0; i < 2; i++ {
		pub, _, err := nikeScheme.GenerateKeyPair()
		require.NoError(t, err)
		replicaPubKeys[i] = pub
	}

	mkemPrivateKey, mkemCiphertext := mkemScheme.Encapsulate(replicaPubKeys, msg.Bytes())
	mkemPublicKey := mkemPrivateKey.Public()

	// Create CourierEnvelope
	return &replicaCommon.CourierEnvelope{
		IntermediateReplicas: [2]uint8{0, 1},
		DEK:                  [2]*[mkem.DEKSize]byte{mkemCiphertext.DEKCiphertexts[0], mkemCiphertext.DEKCiphertexts[1]},
		SenderEPubKey:        mkemPublicKey.Bytes(),
		Ciphertext:           mkemCiphertext.Envelope,
		IsRead:               true,
	}
}

// validateCourierEnvelopeSize performs only the size validation part of handleCourierEnvelope
func validateCourierEnvelopeSize(courier *Courier, courierMessage *replicaCommon.CourierEnvelope) error {
	courier.log.Debugf("Copy: Processing CourierEnvelope (IsRead=%t)", courierMessage.IsRead)

	// Validate CourierEnvelope size against geometry constraints
	envelopeSize := len(courierMessage.Bytes())
	maxEnvelopeSize := max(courier.pigeonholeGeo.CourierQueryReadLength, courier.pigeonholeGeo.CourierQueryWriteLength)
	if envelopeSize > maxEnvelopeSize {
		courier.log.Debugf("Rejecting oversized CourierEnvelope: %d bytes > %d bytes (geometry limit)",
			envelopeSize, maxEnvelopeSize)
		return errGeometryViolation
	}

	// For write operations, validate that the MKEM ciphertext has the exact expected size
	// This ensures BACAP payloads are padded to the maximum size allowed by geometry
	if !courierMessage.IsRead {
		expectedCiphertextSize := courier.pigeonholeGeo.ExpectedMKEMCiphertextSizeForWrite()
		actualCiphertextSize := len(courierMessage.Ciphertext)

		if actualCiphertextSize != expectedCiphertextSize {
			courier.log.Debugf("Rejecting write with incorrect ciphertext size: %d bytes, expected exactly %d bytes (geometry constraint)",
				actualCiphertextSize, expectedCiphertextSize)
			return errGeometryViolation
		}
		courier.log.Debugf("Write ciphertext size validation passed: %d bytes", actualCiphertextSize)
	}

	// Validate DEK array elements are not nil before using them
	if courierMessage.DEK[0] == nil || courierMessage.DEK[1] == nil {
		courier.log.Errorf("handleCourierEnvelope: CourierEnvelope DEK array contains nil elements")
		return errNilDEKElements
	}

	return nil
}
