package server

import (
	"fmt"
	"strings"
	"testing"

	"github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
	kpcommon "github.com/katzenpost/katzenpost/common"
	"github.com/stretchr/testify/require"
)

func TestErrorCategorization(t *testing.T) {
	// Create a minimal state for testing
	st := &state{}

	testCases := []struct {
		error    string
		expected string
	}{
		{"dial tcp: connection refused", "network"},
		{"context deadline exceeded", "timeout"},
		{"handshake failed", "handshake"},
		{"tls: bad certificate", "handshake"},
		{"authentication failed", "auth"},
		{"session creation failed", "session"},
		{"some unknown error", "unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.error, func(t *testing.T) {
			category := st.categorizeError(fmt.Errorf("%s", tc.error))
			require.Equal(t, tc.expected, category)
		})
	}
}

func TestTruncatePEMForLogging(t *testing.T) {
	// Test with a real KEM key to ensure truncation works
	kemScheme := schemes.ByName("X25519")
	require.NotNil(t, kemScheme)

	linkPub, _, err := kemScheme.GenerateKeyPair()
	require.NoError(t, err)

	// Get the full PEM string
	fullPEM := pem.ToPublicPEMString(linkPub)

	// Test truncation
	truncated := kpcommon.TruncatePEMForLogging(fullPEM)

	// Verify structure
	lines := strings.Split(strings.TrimSpace(truncated), "\n")
	require.Equal(t, 2, len(lines), "Truncated PEM should have exactly 2 lines (header, first data line)")

	// Should start with BEGIN header
	require.Contains(t, lines[0], "-----BEGIN")

	// Should be shorter than original
	require.True(t, len(truncated) < len(fullPEM), "Truncated PEM should be shorter than original")

	// Test with short PEM (should not be truncated)
	shortPEM := "-----BEGIN TEST-----\n-----END TEST-----"
	truncatedShort := kpcommon.TruncatePEMForLogging(shortPEM)
	require.Equal(t, shortPEM, truncatedShort, "Short PEM should not be truncated")
}
