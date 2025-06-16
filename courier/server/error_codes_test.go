// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/mkem"

	"github.com/katzenpost/katzenpost/replica/common"
)

const (
	// Test constants to avoid duplication
	testEnvelopeHash = "test-envelope-hash-1234567890123"
)

// TestErrorCodeToString tests the error code to string conversion functions
func TestErrorCodeToString(t *testing.T) {
	// Test copy error codes
	require.Equal(t, "Success", copyErrorToString(copyErrorSuccess))
	require.Equal(t, "Invalid WriteCap", copyErrorToString(copyErrorInvalidWriteCap))
	require.Equal(t, "ReadCap derivation failed", copyErrorToString(copyErrorReadCapDerivation))
	require.Equal(t, "Read operation failed", copyErrorToString(copyErrorRead))
	require.Equal(t, "Empty sequence", copyErrorToString(copyErrorEmptySequence))
	require.Equal(t, "BACAP decryption failed", copyErrorToString(copyErrorBACAPDecryption))
	require.Equal(t, "CBOR decoding failed", copyErrorToString(copyErrorCBORDecoding))
	require.Equal(t, "Streaming decoder failed", copyErrorToString(copyErrorStreamingDecoder))
	require.Equal(t, "Replica timeout", copyErrorToString(copyErrorReplicaTimeout))
	require.Equal(t, "MKEM decryption failed", copyErrorToString(copyErrorMKEMDecryption))
	require.Equal(t, "Tombstone write failed", copyErrorToString(copyErrorTombstoneWrite))
	require.Contains(t, copyErrorToString(255), "Unknown copy error code: 255")

	// Test envelope error codes
	require.Equal(t, "Success", envelopeErrorToString(envelopeErrorSuccess))
	require.Equal(t, "Invalid envelope", envelopeErrorToString(envelopeErrorInvalidEnvelope))
	require.Equal(t, "Nil envelope hash", envelopeErrorToString(envelopeErrorNilEnvelopeHash))
	require.Equal(t, "Nil DEK elements", envelopeErrorToString(envelopeErrorNilDEKElements))
	require.Equal(t, "Invalid replica ID", envelopeErrorToString(envelopeErrorInvalidReplicaID))
	require.Equal(t, "Replica timeout", envelopeErrorToString(envelopeErrorReplicaTimeout))
	require.Equal(t, "Connection failure", envelopeErrorToString(envelopeErrorConnectionFailure))
	require.Equal(t, "Cache corruption", envelopeErrorToString(envelopeErrorCacheCorruption))
	require.Equal(t, "PKI unavailable", envelopeErrorToString(envelopeErrorPKIUnavailable))
	require.Equal(t, "Invalid epoch", envelopeErrorToString(envelopeErrorInvalidEpoch))
	require.Equal(t, "MKEM failure", envelopeErrorToString(envelopeErrorMKEMFailure))
	require.Equal(t, "Replica unavailable", envelopeErrorToString(envelopeErrorReplicaUnavailable))
	require.Equal(t, "Internal error", envelopeErrorToString(envelopeErrorInternalError))
	require.Contains(t, envelopeErrorToString(255), "Unknown envelope error code: 255")

	// Test courier error codes
	require.Equal(t, "Success", courierErrorToString(courierErrorSuccess))
	require.Equal(t, "Invalid command", courierErrorToString(courierErrorInvalidCommand))
	require.Equal(t, "CBOR decoding failed", courierErrorToString(courierErrorCBORDecoding))
	require.Equal(t, "Dispatch failure", courierErrorToString(courierErrorDispatchFailure))
	require.Equal(t, "Connection lost", courierErrorToString(courierErrorConnectionLost))
	require.Equal(t, "Internal error", courierErrorToString(courierErrorInternalError))
	require.Contains(t, courierErrorToString(255), "Unknown courier error code: 255")
}

// TestCreateCopyErrorReply tests the copy error reply creation
func TestCreateCopyErrorReply(t *testing.T) {
	courier := createTestCourier(t)

	reply := courier.createCopyErrorReply(copyErrorEmptySequence)
	require.NotNil(t, reply)
	require.Nil(t, reply.CourierEnvelopeReply)
	require.NotNil(t, reply.CopyCommandReply)
	require.Equal(t, copyErrorEmptySequence, reply.CopyCommandReply.ErrorCode)
}

// TestCreateCopySuccessReply tests the copy success reply creation
func TestCreateCopySuccessReply(t *testing.T) {
	courier := createTestCourier(t)

	reply := courier.createCopySuccessReply()
	require.NotNil(t, reply)
	require.Nil(t, reply.CourierEnvelopeReply)
	require.NotNil(t, reply.CopyCommandReply)
	require.Equal(t, copyErrorSuccess, reply.CopyCommandReply.ErrorCode)
}

// TestCreateEnvelopeErrorReply tests the envelope error reply creation
func TestCreateEnvelopeErrorReply(t *testing.T) {
	courier := createTestCourier(t)
	envHash := &[hash.HashSize]byte{}
	copy(envHash[:], []byte(testEnvelopeHash))

	reply := courier.createEnvelopeErrorReply(envHash, envelopeErrorNilDEKElements)
	require.NotNil(t, reply)
	require.NotNil(t, reply.CourierEnvelopeReply)
	require.Nil(t, reply.CopyCommandReply)
	require.Equal(t, envHash, reply.CourierEnvelopeReply.EnvelopeHash)
	require.Equal(t, envelopeErrorNilDEKElements, reply.CourierEnvelopeReply.ErrorCode)
	require.Equal(t, uint8(0), reply.CourierEnvelopeReply.ReplyIndex)
	require.Nil(t, reply.CourierEnvelopeReply.Payload)
}

// TestHandleOldMessageWithNilCache tests error handling when cache entry is nil
func TestHandleOldMessageWithNilCache(t *testing.T) {
	courier := createTestCourier(t)
	envHash := &[hash.HashSize]byte{}
	copy(envHash[:], []byte(testEnvelopeHash))

	courierMessage := &common.CourierEnvelope{
		ReplyIndex: 0,
	}

	reply := courier.handleOldMessage(nil, envHash, courierMessage)
	require.NotNil(t, reply)
	require.NotNil(t, reply.CourierEnvelopeReply)
	require.Nil(t, reply.CopyCommandReply)
	require.Equal(t, envHash, reply.CourierEnvelopeReply.EnvelopeHash)
	require.Equal(t, envelopeErrorCacheCorruption, reply.CourierEnvelopeReply.ErrorCode)
}

// TestHandleNewMessageWithNilDEK tests error handling when DEK elements are nil
func TestHandleNewMessageWithNilDEK(t *testing.T) {
	courier := createTestCourier(t)
	envHash := &[hash.HashSize]byte{}
	copy(envHash[:], []byte(testEnvelopeHash))

	courierMessage := &common.CourierEnvelope{
		DEK: [2]*[mkem.DEKSize]byte{nil, nil}, // Both DEK elements are nil
	}

	reply := courier.handleNewMessage(envHash, courierMessage)
	require.NotNil(t, reply)
	require.NotNil(t, reply.CourierEnvelopeReply)
	require.Nil(t, reply.CopyCommandReply)
	require.Equal(t, envHash, reply.CourierEnvelopeReply.EnvelopeHash)
	require.Equal(t, envelopeErrorNilDEKElements, reply.CourierEnvelopeReply.ErrorCode)
}
