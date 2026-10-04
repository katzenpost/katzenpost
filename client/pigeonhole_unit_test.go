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
	pos := writeCap.Start()

	testMessage := []byte("Test message for BACAP encryption")
	paddedMessage, err := pigeonhole.CreatePaddedPayload(testMessage, 1557)
	require.NoError(t, err)

	write, err := pigeonhole.Seal(pos, paddedMessage)
	require.NoError(t, err)
	require.NotEmpty(t, write.Payload)

	decryptedPadded, err := pigeonhole.Open(pos.ReadPosition(), write.BoxID, write.Payload, write.Signature[:])
	require.NoError(t, err)

	decryptedMessage, err := pigeonhole.ExtractMessageFromPaddedPayload(decryptedPadded)
	require.NoError(t, err)
	require.Equal(t, testMessage, decryptedMessage, "Decrypted message should match original")

	t.Logf("✓ Successfully encrypted and decrypted message: %d bytes", len(testMessage))
}

// TestBACAPStateAdvancement tests that a position advances correctly
func TestBACAPStateAdvancement(t *testing.T) {
	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)

	first := writeCap.Start()
	firstBoxID, err := pigeonhole.BoxID(first.ReadPosition())
	require.NoError(t, err)

	testMessage1 := []byte("First message")
	paddedMessage1, err := pigeonhole.CreatePaddedPayload(testMessage1, 1557)
	require.NoError(t, err)
	write1, err := pigeonhole.Seal(first, paddedMessage1)
	require.NoError(t, err)
	require.Equal(t, firstBoxID, write1.BoxID, "BoxID should match calculated value")

	second, err := first.Next()
	require.NoError(t, err)
	secondBoxID, err := pigeonhole.BoxID(second.ReadPosition())
	require.NoError(t, err)
	require.NotEqual(t, firstBoxID, secondBoxID, "BoxID should change after the index advances")

	testMessage2 := []byte("Second message")
	paddedMessage2, err := pigeonhole.CreatePaddedPayload(testMessage2, 1557)
	require.NoError(t, err)
	write2, err := pigeonhole.Seal(second, paddedMessage2)
	require.NoError(t, err)
	require.Equal(t, secondBoxID, write2.BoxID, "Second BoxID should match calculated value")

	// A reader starting at the cap's own index opens both, advancing in between.
	reader := writeCap.ReadCap().Start()
	decrypted1, err := pigeonhole.Open(reader, write1.BoxID, write1.Payload, write1.Signature[:])
	require.NoError(t, err)
	unpadded1, err := pigeonhole.ExtractMessageFromPaddedPayload(decrypted1)
	require.NoError(t, err)
	require.Equal(t, testMessage1, unpadded1, "First message should match")

	reader, err = reader.Next()
	require.NoError(t, err)
	decrypted2, err := pigeonhole.Open(reader, write2.BoxID, write2.Payload, write2.Signature[:])
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
	pos := writeCap.Start()

	testMessage := []byte("Test message")
	paddedMessage, err := pigeonhole.CreatePaddedPayload(testMessage, 1557)
	require.NoError(t, err)
	write, err := pigeonhole.Seal(pos, paddedMessage)
	require.NoError(t, err)

	// The next position's box is a different BoxID
	next, err := pos.Next()
	require.NoError(t, err)
	wrong, err := pigeonhole.Seal(next, paddedMessage)
	require.NoError(t, err)

	_, err = pigeonhole.Open(pos.ReadPosition(), wrong.BoxID, write.Payload, write.Signature[:])
	require.ErrorIs(t, err, bacap.ErrBoxMismatch, "Decryption should fail with wrong BoxID")

	decrypted, err := pigeonhole.Open(pos.ReadPosition(), write.BoxID, write.Payload, write.Signature[:])
	require.NoError(t, err, "Decryption should succeed with correct BoxID")
	unpadded, err := pigeonhole.ExtractMessageFromPaddedPayload(decrypted)
	require.NoError(t, err)
	require.Equal(t, testMessage, unpadded)

	t.Logf("✓ Correctly rejected decryption with wrong BoxID")
}
