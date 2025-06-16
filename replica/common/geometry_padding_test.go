// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"testing"

	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/stretchr/testify/require"
)

func TestGeometryPaddingCalculations(t *testing.T) {
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	// Test with different BoxPayloadLength values
	testCases := []struct {
		name             string
		boxPayloadLength int
	}{
		{"small_payload", 100},
		{"medium_payload", 1000},
		{"large_payload", 2000},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			geo := NewGeometry(tc.boxPayloadLength, nikeScheme)

			// Verify that BoxPayloadLength represents the maximum user data
			require.Equal(t, tc.boxPayloadLength, geo.BoxPayloadLength)

			// Verify that PaddedPayloadLength includes the 4-byte overhead
			expectedPaddedLength := tc.boxPayloadLength + 4
			require.Equal(t, expectedPaddedLength, geo.PaddedPayloadLength())

			// Test that we can create padded payloads up to BoxPayloadLength
			maxUserData := make([]byte, tc.boxPayloadLength)
			paddedPayload, err := CreatePaddedPayload(maxUserData, tc.boxPayloadLength)
			require.NoError(t, err)
			require.Equal(t, expectedPaddedLength, len(paddedPayload))

			// Test that we can extract the original data
			extractedData, err := ExtractDataFromPaddedPayload(paddedPayload)
			require.NoError(t, err)
			require.Equal(t, maxUserData, extractedData)

			// Test that data larger than BoxPayloadLength is rejected
			tooLargeData := make([]byte, tc.boxPayloadLength+1)
			_, err = CreatePaddedPayload(tooLargeData, tc.boxPayloadLength)
			require.Error(t, err)
		})
	}
}

func TestGeometryValidation(t *testing.T) {
	nikeScheme := schemes.ByName("x25519")
	require.NotNil(t, nikeScheme)

	geo := NewGeometry(1000, nikeScheme)
	require.NoError(t, geo.Validate())

	// Test that geometry calculations are consistent
	require.Greater(t, geo.CourierQueryWriteLength, 0)
	require.Greater(t, geo.CourierQueryReadLength, 0)
	require.Greater(t, geo.CourierQueryReplyWriteLength, 0)
	require.Greater(t, geo.CourierQueryReplyReadLength, 0)

	// Test that write operations account for the padded payload
	expectedCiphertextSize := geo.ExpectedMKEMCiphertextSizeForWrite()
	require.Greater(t, expectedCiphertextSize, geo.PaddedPayloadLength())
}
