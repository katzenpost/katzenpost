// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client2

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/katzenpost/katzenpost/pigeonhole"
)

// TestPaddingRoundTrip tests that CreatePaddedPayload and ExtractMessageFromPaddedPayload work correctly
func TestPaddingRoundTrip(t *testing.T) {
	testCases := []struct {
		name       string
		message    []byte
		targetSize int
	}{
		{
			name:       "Short message",
			message:    []byte("Hello, World!"),
			targetSize: 1557, // MaxPlaintextPayloadLength + 4
		},
		{
			name:       "Empty message",
			message:    []byte{},
			targetSize: 1557,
		},
		{
			name:       "Long message",
			message:    make([]byte, 1500),
			targetSize: 1557,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Pad the message
			paddedMessage, err := pigeonhole.CreatePaddedPayload(tc.message, tc.targetSize)
			require.NoError(t, err)
			require.Equal(t, tc.targetSize, len(paddedMessage), "Padded message should match target size")

			// Unpad the message
			unpaddedMessage, err := pigeonhole.ExtractMessageFromPaddedPayload(paddedMessage)
			require.NoError(t, err)
			require.Equal(t, tc.message, unpaddedMessage, "Unpadded message should match original")

			t.Logf("✓ Successfully padded and unpadded message: %d bytes → %d bytes → %d bytes",
				len(tc.message), len(paddedMessage), len(unpaddedMessage))
		})
	}
}

// TestPaddingInvalidCases tests error handling for invalid padding
func TestPaddingInvalidCases(t *testing.T) {
	t.Run("Message too large", func(t *testing.T) {
		message := make([]byte, 2000)
		targetSize := 1557

		_, err := pigeonhole.CreatePaddedPayload(message, targetSize)
		require.Error(t, err, "Should fail when message is too large")
		require.Contains(t, err.Error(), "exceeds target size")
	})

	t.Run("Invalid padding - too short", func(t *testing.T) {
		invalidPadded := []byte{0x00, 0x01} // Too short to contain length prefix

		_, err := pigeonhole.ExtractMessageFromPaddedPayload(invalidPadded)
		require.Error(t, err, "Should fail when padded payload is too short")
		require.Contains(t, err.Error(), "too short")
	})

	t.Run("Invalid padding - length mismatch", func(t *testing.T) {
		// Length prefix says 100 bytes but payload only has 10
		invalidPadded := []byte{0, 0, 0, 100, 1, 2, 3, 4, 5, 6}

		_, err := pigeonhole.ExtractMessageFromPaddedPayload(invalidPadded)
		require.Error(t, err, "Should fail when length prefix is invalid")
		require.Contains(t, err.Error(), "invalid message length")
	})
}

// TestBACAPBoxIDDerivation tests that BoxIDForContext produces consistent results
func TestBACAPBoxIDDerivation(t *testing.T) {
	// Create a WriteCap
	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)

	readCap := writeCap.ReadCap()

	// Create a StatefulWriter
	statefulWriter, err := bacap.NewStatefulWriter(writeCap, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)

	// Get the current message index
	messageBoxIndex := statefulWriter.GetCurrentMessageIndex()

	// Derive BoxID using BoxIDForContext (correct method)
	boxID1 := messageBoxIndex.BoxIDForContext(readCap, constants.PIGEONHOLE_CTX)
	boxID2 := messageBoxIndex.BoxIDForContext(readCap, constants.PIGEONHOLE_CTX)

	// BoxID should be deterministic
	require.Equal(t, boxID1.Bytes(), boxID2.Bytes(), "BoxID derivation should be deterministic")

	t.Logf("✓ BoxID derivation is deterministic: %x", boxID1.Bytes())
}

// TestBACAPEncryptionDecryption tests that BACAP encryption and decryption work correctly
func TestBACAPEncryptionDecryption(t *testing.T) {
	// Create a WriteCap
	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)

	readCap := writeCap.ReadCap()

	// Create a StatefulWriter
	statefulWriter, err := bacap.NewStatefulWriter(writeCap, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)

	// Get the current message index
	messageBoxIndex := statefulWriter.GetCurrentMessageIndex()

	// Create a test message
	testMessage := []byte("Test message for BACAP encryption")

	// Pad the message
	paddedMessage, err := pigeonhole.CreatePaddedPayload(testMessage, 1557)
	require.NoError(t, err)

	// Encrypt the message
	boxID, ciphertext, signature, err := statefulWriter.EncryptNext(paddedMessage)
	require.NoError(t, err)
	require.NotNil(t, boxID)
	require.NotNil(t, ciphertext)
	require.NotNil(t, signature)

	// Create a StatefulReader with the same index
	statefulReader, err := bacap.NewStatefulReaderWithIndex(readCap, constants.PIGEONHOLE_CTX, messageBoxIndex)
	require.NoError(t, err)

	// Convert signature to array
	var sigArray [64]byte
	copy(sigArray[:], signature)

	// Decrypt the message
	decryptedPadded, err := statefulReader.DecryptNext(constants.PIGEONHOLE_CTX, boxID, ciphertext, sigArray)
	require.NoError(t, err)

	// Unpad the decrypted message
	decryptedMessage, err := pigeonhole.ExtractMessageFromPaddedPayload(decryptedPadded)
	require.NoError(t, err)

	// Verify the message matches
	require.Equal(t, testMessage, decryptedMessage, "Decrypted message should match original")

	t.Logf("✓ Successfully encrypted and decrypted message: %d bytes", len(testMessage))
}

// TestBACAPStateAdvancement tests that message box index advances correctly
func TestBACAPStateAdvancement(t *testing.T) {
	// Create a WriteCap
	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)

	readCap := writeCap.ReadCap()

	// Create a StatefulWriter
	statefulWriter, err := bacap.NewStatefulWriter(writeCap, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)

	// Get the first message index
	firstIndex := statefulWriter.GetCurrentMessageIndex()
	firstBoxID := firstIndex.BoxIDForContext(readCap, constants.PIGEONHOLE_CTX)

	// Encrypt first message
	testMessage1 := []byte("First message")
	paddedMessage1, err := pigeonhole.CreatePaddedPayload(testMessage1, 1557)
	require.NoError(t, err)

	boxID1, ciphertext1, signature1, err := statefulWriter.EncryptNext(paddedMessage1)
	require.NoError(t, err)

	// Verify the boxID matches what we calculated
	require.Equal(t, firstBoxID.Bytes(), boxID1[:], "BoxID should match calculated value")

	// Get the second message index (state should have advanced)
	secondIndex := statefulWriter.GetCurrentMessageIndex()
	secondBoxID := secondIndex.BoxIDForContext(readCap, constants.PIGEONHOLE_CTX)

	// BoxIDs should be different after state advancement
	require.NotEqual(t, firstBoxID.Bytes(), secondBoxID.Bytes(), "BoxID should change after state advancement")

	// Encrypt second message
	testMessage2 := []byte("Second message")
	paddedMessage2, err := pigeonhole.CreatePaddedPayload(testMessage2, 1557)
	require.NoError(t, err)

	boxID2, ciphertext2, signature2, err := statefulWriter.EncryptNext(paddedMessage2)
	require.NoError(t, err)

	// Verify the second boxID matches
	require.Equal(t, secondBoxID.Bytes(), boxID2[:], "Second BoxID should match calculated value")

	// Create a StatefulReader starting at the first index
	statefulReader, err := bacap.NewStatefulReaderWithIndex(readCap, constants.PIGEONHOLE_CTX, firstIndex)
	require.NoError(t, err)

	// Decrypt first message
	var sig1Array [64]byte
	copy(sig1Array[:], signature1)
	decrypted1, err := statefulReader.DecryptNext(constants.PIGEONHOLE_CTX, boxID1, ciphertext1, sig1Array)
	require.NoError(t, err)

	unpadded1, err := pigeonhole.ExtractMessageFromPaddedPayload(decrypted1)
	require.NoError(t, err)
	require.Equal(t, testMessage1, unpadded1, "First message should match")

	// Decrypt second message (reader state should have advanced)
	var sig2Array [64]byte
	copy(sig2Array[:], signature2)
	decrypted2, err := statefulReader.DecryptNext(constants.PIGEONHOLE_CTX, boxID2, ciphertext2, sig2Array)
	require.NoError(t, err)

	unpadded2, err := pigeonhole.ExtractMessageFromPaddedPayload(decrypted2)
	require.NoError(t, err)
	require.Equal(t, testMessage2, unpadded2, "Second message should match")

	t.Logf("✓ Successfully encrypted and decrypted 2 messages with state advancement")
}

// TestBACAPBoxIDMismatch tests that decryption fails with wrong BoxID
func TestBACAPBoxIDMismatch(t *testing.T) {
	// Create a WriteCap
	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)

	readCap := writeCap.ReadCap()

	// Create a StatefulWriter
	statefulWriter, err := bacap.NewStatefulWriter(writeCap, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)

	messageIndex := statefulWriter.GetCurrentMessageIndex()

	// Encrypt a message
	testMessage := []byte("Test message")
	paddedMessage, err := pigeonhole.CreatePaddedPayload(testMessage, 1557)
	require.NoError(t, err)

	correctBoxID, ciphertext, signature, err := statefulWriter.EncryptNext(paddedMessage)
	require.NoError(t, err)

	// Create a different BoxID (advance state and get next BoxID)
	wrongBoxID, _, _, err := statefulWriter.EncryptNext(paddedMessage)
	require.NoError(t, err)

	// Create a StatefulReader at the original index
	statefulReader, err := bacap.NewStatefulReaderWithIndex(readCap, constants.PIGEONHOLE_CTX, messageIndex)
	require.NoError(t, err)

	// Try to decrypt with the WRONG BoxID - should fail
	var sigArray [64]byte
	copy(sigArray[:], signature)
	_, err = statefulReader.DecryptNext(constants.PIGEONHOLE_CTX, wrongBoxID, ciphertext, sigArray)
	require.Error(t, err, "Decryption should fail with wrong BoxID")

	// Try to decrypt with the CORRECT BoxID - should succeed
	decrypted, err := statefulReader.DecryptNext(constants.PIGEONHOLE_CTX, correctBoxID, ciphertext, sigArray)
	require.NoError(t, err, "Decryption should succeed with correct BoxID")

	unpadded, err := pigeonhole.ExtractMessageFromPaddedPayload(decrypted)
	require.NoError(t, err)
	require.Equal(t, testMessage, unpadded)

	t.Logf("✓ Correctly rejected decryption with wrong BoxID")
}
