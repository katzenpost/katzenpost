// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonhole

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreatePaddedPayload(t *testing.T) {
	t.Run("BasicPadding", func(t *testing.T) {
		message := []byte("Hello, World!")
		targetSize := 100

		paddedPayload, err := CreatePaddedPayload(message, targetSize)
		require.NoError(t, err)
		require.Equal(t, targetSize, len(paddedPayload))

		// Extract the message back
		extractedMessage, err := ExtractMessageFromPaddedPayload(paddedPayload)
		require.NoError(t, err)
		require.Equal(t, message, extractedMessage)
	})

	t.Run("MessageTooLarge", func(t *testing.T) {
		message := make([]byte, 100)
		targetSize := 50 // Too small for message + 4-byte prefix

		_, err := CreatePaddedPayload(message, targetSize)
		require.Error(t, err)
		require.Contains(t, err.Error(), "exceeds target size")
	})

	t.Run("ExactFit", func(t *testing.T) {
		message := []byte("test")
		targetSize := 8 // 4 bytes for prefix + 4 bytes for message

		paddedPayload, err := CreatePaddedPayload(message, targetSize)
		require.NoError(t, err)
		require.Equal(t, targetSize, len(paddedPayload))

		extractedMessage, err := ExtractMessageFromPaddedPayload(paddedPayload)
		require.NoError(t, err)
		require.Equal(t, message, extractedMessage)
	})

	t.Run("EmptyMessage", func(t *testing.T) {
		message := []byte{}
		targetSize := 10

		paddedPayload, err := CreatePaddedPayload(message, targetSize)
		require.NoError(t, err)
		require.Equal(t, targetSize, len(paddedPayload))

		extractedMessage, err := ExtractMessageFromPaddedPayload(paddedPayload)
		require.NoError(t, err)
		require.Equal(t, message, extractedMessage)
	})

	t.Run("LengthPrefixValidation", func(t *testing.T) {
		message := []byte("test message")
		targetSize := 50

		paddedPayload, err := CreatePaddedPayload(message, targetSize)
		require.NoError(t, err)

		// Check that the length prefix is correct
		expectedLength := uint32(len(message))
		actualLength := uint32(paddedPayload[0])<<24 | uint32(paddedPayload[1])<<16 | uint32(paddedPayload[2])<<8 | uint32(paddedPayload[3])
		require.Equal(t, expectedLength, actualLength)

		// Check that the message is at the right position
		actualMessage := paddedPayload[4 : 4+len(message)]
		require.Equal(t, message, actualMessage)

		// Check that the rest is zero padding
		padding := paddedPayload[4+len(message):]
		for i, b := range padding {
			require.Equal(t, uint8(0), b, "padding byte %d should be zero", i)
		}
	})
}

func TestExtractMessageFromPaddedPayload(t *testing.T) {
	t.Run("InvalidLength", func(t *testing.T) {
		// Too short for length prefix
		shortPayload := []byte{1, 2}
		_, err := ExtractMessageFromPaddedPayload(shortPayload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "too short")
	})

	t.Run("InvalidMessageLength", func(t *testing.T) {
		// Length prefix says 100 bytes but payload only has 10
		invalidPayload := []byte{0, 0, 0, 100, 1, 2, 3, 4, 5, 6}
		_, err := ExtractMessageFromPaddedPayload(invalidPayload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid message length")
	})
}
