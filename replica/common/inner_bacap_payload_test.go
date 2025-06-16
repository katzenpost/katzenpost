// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreatePaddedPayload(t *testing.T) {
	tests := []struct {
		name            string
		data            []byte
		maxUserDataSize int
		expectError     bool
	}{
		{
			name:            "small data",
			data:            []byte("hello"),
			maxUserDataSize: 100,
			expectError:     false,
		},
		{
			name:            "empty data",
			data:            []byte{},
			maxUserDataSize: 100,
			expectError:     false,
		},
		{
			name:            "data too large",
			data:            make([]byte, 100),
			maxUserDataSize: 50,
			expectError:     true,
		},
		{
			name:            "exact fit",
			data:            make([]byte, 100), // Exactly maxUserDataSize
			maxUserDataSize: 100,
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paddedPayload, err := CreatePaddedPayload(tt.data, tt.maxUserDataSize)

			if tt.expectError {
				require.Error(t, err)
				require.Nil(t, paddedPayload)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, paddedPayload)
			expectedTotalSize := tt.maxUserDataSize + 4
			require.Equal(t, expectedTotalSize, len(paddedPayload), "Padded payload should be maxUserDataSize + 4 bytes")

			// Verify the length prefix
			expectedLength := uint32(len(tt.data))
			actualLength := binary.LittleEndian.Uint32(paddedPayload[0:4])
			require.Equal(t, expectedLength, actualLength, "Length prefix should match data length")

			// Verify the data portion
			actualData := paddedPayload[4 : 4+len(tt.data)]
			require.Equal(t, tt.data, actualData, "Data portion should match original data")

			// Verify padding is all zeros
			padding := paddedPayload[4+len(tt.data):]
			expectedPadding := make([]byte, len(padding))
			require.Equal(t, expectedPadding, padding, "Padding should be all zeros")
		})
	}
}

func TestExtractDataFromPaddedPayload(t *testing.T) {
	tests := []struct {
		name            string
		data            []byte
		maxUserDataSize int
		expectError     bool
	}{
		{
			name:            "small data",
			data:            []byte("hello world"),
			maxUserDataSize: 100,
			expectError:     false,
		},
		{
			name:            "empty data",
			data:            []byte{},
			maxUserDataSize: 100,
			expectError:     false,
		},
		{
			name:            "binary data",
			data:            []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			maxUserDataSize: 100,
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// First create a padded payload
			paddedPayload, err := CreatePaddedPayload(tt.data, tt.maxUserDataSize)
			require.NoError(t, err)

			// Then extract the data back
			extractedData, err := ExtractDataFromPaddedPayload(paddedPayload)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.data, extractedData, "Extracted data should match original data")
		})
	}
}

func TestExtractDataFromPaddedPayloadErrors(t *testing.T) {
	tests := []struct {
		name          string
		paddedPayload []byte
		expectedError string
	}{
		{
			name:          "too short",
			paddedPayload: []byte{0x01, 0x02},
			expectedError: "padded payload too short",
		},
		{
			name:          "invalid length",
			paddedPayload: append([]byte{0xFF, 0xFF, 0xFF, 0xFF}, make([]byte, 10)...),
			expectedError: "invalid data length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractedData, err := ExtractDataFromPaddedPayload(tt.paddedPayload)
			require.Error(t, err)
			require.Nil(t, extractedData)
			require.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

func TestRoundTripWithDifferentSizes(t *testing.T) {
	// Test with various data sizes and max user data sizes
	testData := [][]byte{
		[]byte("short"),
		[]byte("this is a longer message that should still work fine"),
		make([]byte, 500), // Large binary data
		[]byte{},          // Empty data
	}

	maxUserDataSizes := []int{100, 1000, 2000}

	for _, data := range testData {
		for _, maxUserDataSize := range maxUserDataSizes {
			if len(data) > maxUserDataSize {
				continue // Skip combinations that would fail
			}

			t.Run(fmt.Sprintf("data_len_%d_max_%d", len(data), maxUserDataSize), func(t *testing.T) {
				// Create padded payload
				paddedPayload, err := CreatePaddedPayload(data, maxUserDataSize)
				require.NoError(t, err)
				expectedTotalSize := maxUserDataSize + 4
				require.Equal(t, expectedTotalSize, len(paddedPayload))

				// Extract data back
				extractedData, err := ExtractDataFromPaddedPayload(paddedPayload)
				require.NoError(t, err)
				require.Equal(t, data, extractedData)
			})
		}
	}
}

func TestPaddingIsZeros(t *testing.T) {
	data := []byte("test data")
	maxUserDataSize := 100

	paddedPayload, err := CreatePaddedPayload(data, maxUserDataSize)
	require.NoError(t, err)

	// Check that all padding bytes are zero
	paddingStart := 4 + len(data)
	padding := paddedPayload[paddingStart:]

	for i, b := range padding {
		require.Equal(t, byte(0), b, "Padding byte at index %d should be zero", i)
	}
}
