// SPDX-FileCopyrightText: Copyright (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"strings"
	"testing"

	"github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/stretchr/testify/require"
)

func TestTruncatePEMForLogging(t *testing.T) {
	// Test with a real KEM key to ensure truncation works
	kemScheme := schemes.ByName("X25519")
	require.NotNil(t, kemScheme)

	linkPub, _, err := kemScheme.GenerateKeyPair()
	require.NoError(t, err)

	// Get the full PEM string
	fullPEM := pem.ToPublicPEMString(linkPub)
	
	// Test truncation
	truncated := TruncatePEMForLogging(fullPEM)
	
	// Verify structure
	lines := strings.Split(strings.TrimSpace(truncated), "\n")
	require.True(t, len(lines) >= 3, "Truncated PEM should have at least 3 lines (header, first data line, ...)")
	
	// Should end with "..."
	require.Equal(t, "...", lines[len(lines)-1])
	
	// Should be shorter than original
	require.True(t, len(truncated) < len(fullPEM), "Truncated PEM should be shorter than original")
	
	// Test with short PEM (should not be truncated)
	shortPEM := "-----BEGIN TEST-----\n-----END TEST-----"
	truncatedShort := TruncatePEMForLogging(shortPEM)
	require.Equal(t, shortPEM, truncatedShort, "Short PEM should not be truncated")
}
