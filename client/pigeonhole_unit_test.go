// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client/constants"
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
	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	readCap := writeCap.ReadCap()
	messageBoxIndex := writeCap.GetMessageBoxIndex()

	boxID1, err := messageBoxIndex.BoxIDForContext(readCap, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)
	boxID2, err := messageBoxIndex.BoxIDForContext(readCap, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)

	// BoxID should be deterministic
	require.Equal(t, boxID1.Bytes(), boxID2.Bytes(), "BoxID derivation should be deterministic")

	t.Logf("✓ BoxID derivation is deterministic: %x", boxID1.Bytes())
}

// TestBACAPEncryptionDecryption tests that BACAP encryption and decryption work correctly
func TestBACAPEncryptionDecryption(t *testing.T) {
	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	readCap := writeCap.ReadCap()
	messageBoxIndex := writeCap.GetMessageBoxIndex()

	testMessage := []byte("Test message for BACAP encryption")
	paddedMessage, err := pigeonhole.CreatePaddedPayload(testMessage, 1557)
	require.NoError(t, err)

	boxID, ciphertext, signature, err := messageBoxIndex.EncryptForContext(writeCap, constants.PIGEONHOLE_CTX, paddedMessage)
	require.NoError(t, err)
	require.NotNil(t, ciphertext)
	require.NotNil(t, signature)

	decryptedPadded, err := pigeonhole.OpenBox(readCap, messageBoxIndex, constants.PIGEONHOLE_CTX, boxID, ciphertext, signature)
	require.NoError(t, err)

	decryptedMessage, err := pigeonhole.ExtractMessageFromPaddedPayload(decryptedPadded)
	require.NoError(t, err)
	require.Equal(t, testMessage, decryptedMessage, "Decrypted message should match original")

	t.Logf("✓ Successfully encrypted and decrypted message: %d bytes", len(testMessage))
}

// TestBACAPStateAdvancement tests that message box index advances correctly
func TestBACAPStateAdvancement(t *testing.T) {
	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	readCap := writeCap.ReadCap()

	firstIndex := writeCap.GetMessageBoxIndex()
	firstBoxID, err := firstIndex.BoxIDForContext(readCap, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)

	testMessage1 := []byte("First message")
	paddedMessage1, err := pigeonhole.CreatePaddedPayload(testMessage1, 1557)
	require.NoError(t, err)
	boxID1, ciphertext1, signature1, err := firstIndex.EncryptForContext(writeCap, constants.PIGEONHOLE_CTX, paddedMessage1)
	require.NoError(t, err)
	require.Equal(t, firstBoxID.Bytes(), boxID1[:], "BoxID should match calculated value")

	secondIndex, err := firstIndex.NextIndex()
	require.NoError(t, err)
	secondBoxID, err := secondIndex.BoxIDForContext(readCap, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)
	require.NotEqual(t, firstBoxID.Bytes(), secondBoxID.Bytes(), "BoxID should change after the index advances")

	testMessage2 := []byte("Second message")
	paddedMessage2, err := pigeonhole.CreatePaddedPayload(testMessage2, 1557)
	require.NoError(t, err)
	boxID2, ciphertext2, signature2, err := secondIndex.EncryptForContext(writeCap, constants.PIGEONHOLE_CTX, paddedMessage2)
	require.NoError(t, err)
	require.Equal(t, secondBoxID.Bytes(), boxID2[:], "Second BoxID should match calculated value")

	// A reader starting at the first index opens both, advancing in between.
	readIndex := readCap.GetMessageBoxIndex()
	decrypted1, err := pigeonhole.OpenBox(readCap, readIndex, constants.PIGEONHOLE_CTX, boxID1, ciphertext1, signature1)
	require.NoError(t, err)
	unpadded1, err := pigeonhole.ExtractMessageFromPaddedPayload(decrypted1)
	require.NoError(t, err)
	require.Equal(t, testMessage1, unpadded1, "First message should match")

	readIndex, err = readIndex.NextIndex()
	require.NoError(t, err)
	decrypted2, err := pigeonhole.OpenBox(readCap, readIndex, constants.PIGEONHOLE_CTX, boxID2, ciphertext2, signature2)
	require.NoError(t, err)
	unpadded2, err := pigeonhole.ExtractMessageFromPaddedPayload(decrypted2)
	require.NoError(t, err)
	require.Equal(t, testMessage2, unpadded2, "Second message should match")

	t.Logf("✓ Successfully encrypted and decrypted 2 messages with state advancement")
}

// TestBACAPBoxIDMismatch tests that decryption fails with wrong BoxID
func TestBACAPBoxIDMismatch(t *testing.T) {
	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	readCap := writeCap.ReadCap()
	messageIndex := writeCap.GetMessageBoxIndex()

	testMessage := []byte("Test message")
	paddedMessage, err := pigeonhole.CreatePaddedPayload(testMessage, 1557)
	require.NoError(t, err)
	correctBoxID, ciphertext, signature, err := messageIndex.EncryptForContext(writeCap, constants.PIGEONHOLE_CTX, paddedMessage)
	require.NoError(t, err)

	// The next index's box is a different BoxID
	nextIndex, err := messageIndex.NextIndex()
	require.NoError(t, err)
	wrongBoxID, _, _, err := nextIndex.EncryptForContext(writeCap, constants.PIGEONHOLE_CTX, paddedMessage)
	require.NoError(t, err)

	_, err = pigeonhole.OpenBox(readCap, messageIndex, constants.PIGEONHOLE_CTX, wrongBoxID, ciphertext, signature)
	require.ErrorIs(t, err, pigeonhole.ErrBoxMismatch, "Decryption should fail with wrong BoxID")

	decrypted, err := pigeonhole.OpenBox(readCap, messageIndex, constants.PIGEONHOLE_CTX, correctBoxID, ciphertext, signature)
	require.NoError(t, err, "Decryption should succeed with correct BoxID")
	unpadded, err := pigeonhole.ExtractMessageFromPaddedPayload(decrypted)
	require.NoError(t, err)
	require.Equal(t, testMessage, unpadded)

	t.Logf("✓ Correctly rejected decryption with wrong BoxID")
}
