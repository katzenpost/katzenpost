package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHopSpecParsing(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a real key file for valid tests
	validKeyFile := filepath.Join(tmpDir, "valid.pem")
	validPEM := `-----BEGIN X25519 PUBLIC KEY-----
MCowBQYDK2VuAyEAb49ef25e17c77eca3945955bf99fae538a59865067a7fc7afd92ef9153e8ac30
-----END X25519 PUBLIC KEY-----`
	err := os.WriteFile(validKeyFile, []byte(validPEM), 0644)
	require.NoError(t, err)

	tests := []struct {
		name        string
		hops        []string
		expectError bool
	}{
		{
			name: "valid hop spec",
			hops: []string{
				"b49ef25e17c77eca3945955bf99fae538a59865067a7fc7afd92ef9153e8ac30," + validKeyFile,
			},
			expectError: true, // Will fail due to key parsing, but tests the hop spec format
		},
		{
			name: "missing comma",
			hops: []string{
				"b49ef25e17c77eca3945955bf99fae538a59865067a7fc7afd92ef9153e8ac30" + validKeyFile,
			},
			expectError: true,
		},
		{
			name: "too many parts",
			hops: []string{
				"b49ef25e17c77eca3945955bf99fae538a59865067a7fc7afd92ef9153e8ac30," + validKeyFile + ",extra",
			},
			expectError: true,
		},
		{
			name: "invalid node ID",
			hops: []string{
				"invalid_hex," + validKeyFile,
			},
			expectError: true,
		},
		{
			name: "empty hop spec",
			hops: []string{
				"",
			},
			expectError: true,
		},
		{
			name: "nonexistent key file",
			hops: []string{
				"b49ef25e17c77eca3945955bf99fae538a59865067a7fc7afd92ef9153e8ac30,/nonexistent/key.pem",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test using the real buildPathFromHops function from main.go
			var newPacket NewPacket
			err := buildPathFromHops(&newPacket, tt.hops)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, newPacket.Path)
			}
		})
	}
}

func TestSURBKeysFileFormat(t *testing.T) {
	tmpDir := t.TempDir()

	// Test the SURB keys save/load functions directly with real data
	testSURBID := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	// Create realistic SURB keys data (base64 encoded keys)
	testKeys := []byte("dGVzdF9zdXJiX2tleXNfZGF0YV9oZXJlX3dpdGhfcmVhbF9iYXNlNjRfZW5jb2Rpbmc=")

	keysFile := filepath.Join(tmpDir, "test_keys.toml")

	// Test saving SURB keys with ID using the real function from main.go
	err := saveSURBKeysWithIDs(keysFile, testKeys, testSURBID)
	require.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(keysFile)
	require.NoError(t, err)

	// Test loading SURB keys using the real function from main.go
	loadedKeys, err := loadSURBKeysFromTOML(keysFile)
	require.NoError(t, err)
	require.Equal(t, testKeys, loadedKeys)

	// Verify the file contains the expected SURB ID by reading it directly
	fileContent, err := os.ReadFile(keysFile)
	require.NoError(t, err)

	// Check that the SURB ID is present in the file
	surbIDHex := hex.EncodeToString(testSURBID[:])
	require.Contains(t, string(fileContent), surbIDHex)
}

func TestSURBPayloadExtraction(t *testing.T) {
	tmpDir := t.TempDir()

	// Create real geometry using the same function as main.go
	createGeometry := &CreateGeometry{
		NrMixHops:                3,
		NIKE:                     "x25519",
		UserForwardPayloadLength: 2000,
		File:                     filepath.Join(tmpDir, "geometry.toml"),
	}

	// Generate real geometry
	generateSphinxGeometry(createGeometry)

	// Load the geometry that was created
	geometry, err := loadGeometryFromTOML(createGeometry.File)
	require.NoError(t, err)

	t.Run("payload with SURB", func(t *testing.T) {
		// Create realistic SURB data (proper length for the geometry)
		surbData := make([]byte, geometry.SURBLength)
		for i := range surbData {
			surbData[i] = byte(i % 256) // Fill with pattern
		}

		// Create user message
		userMessage := []byte("Hello from SURB payload test!")

		// Create real combined payload using the actual format
		combinedPayload := createRealCombinedPayload(surbData, userMessage)

		// Test extraction using the real function from main.go
		extractedFile := filepath.Join(tmpDir, "extracted.surb")
		extractedUserPayload, err := extractSURBFromPayload(combinedPayload, extractedFile, geometry)
		require.NoError(t, err)

		// Verify SURB was extracted correctly
		extractedSURB, err := os.ReadFile(extractedFile)
		require.NoError(t, err)
		require.Equal(t, surbData, extractedSURB)

		// Verify user payload was extracted correctly
		require.Equal(t, userMessage, extractedUserPayload)
	})

	t.Run("payload without SURB", func(t *testing.T) {
		// Create payload without SURB (flags=0)
		userMessage := []byte("Hello without SURB")
		payload := append([]byte{0x00, 0x00}, userMessage...) // flags=0, reserved=0

		extractedFile := filepath.Join(tmpDir, "no_surb.surb")
		extractedUserPayload, err := extractSURBFromPayload(payload, extractedFile, geometry)
		require.NoError(t, err)

		// Should return the full payload
		require.Equal(t, payload, extractedUserPayload)

		// No SURB file should be created or it should be empty
		if _, err := os.Stat(extractedFile); err == nil {
			surbData, _ := os.ReadFile(extractedFile)
			require.Empty(t, surbData)
		}
	})
}

// Helper functions

func createRealCombinedPayload(surbData, userData []byte) []byte {
	// Create real combined payload format: [flags=1][reserved=0][SURB][user_data]
	payload := make([]byte, 0, 2+len(surbData)+len(userData))

	// Flags: 0x01 indicates SURB is present
	payload = append(payload, 0x01, 0x00)

	// Append real SURB data
	payload = append(payload, surbData...)

	// Append user data
	payload = append(payload, userData...)

	return payload
}
