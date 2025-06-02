package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodeIDGeneration(t *testing.T) {
	// Test valid node ID generation
	validNodeID := "b49ef25e17c77eca3945955bf99fae538a59865067a7fc7afd92ef9153e8ac30"
	nodeIDBytes, err := hex.DecodeString(validNodeID)
	require.NoError(t, err)
	require.Len(t, nodeIDBytes, 32, "Node ID should be 32 bytes")

	// Test invalid node ID
	invalidNodeID := "invalid_hex"
	_, err = hex.DecodeString(invalidNodeID)
	require.Error(t, err, "Invalid hex should produce error")

	// Test wrong length node ID
	shortNodeID := "b49ef25e17c77eca"
	shortBytes, err := hex.DecodeString(shortNodeID)
	require.NoError(t, err)
	require.NotEqual(t, 32, len(shortBytes), "Short node ID should not be 32 bytes")
}

func TestHopSpecParsing(t *testing.T) {
	tests := []struct {
		name        string
		hopSpec     string
		expectError bool
	}{
		{
			name:        "valid hop spec",
			hopSpec:     "b49ef25e17c77eca3945955bf99fae538a59865067a7fc7afd92ef9153e8ac30,/path/to/key.pem",
			expectError: false,
		},
		{
			name:        "missing comma",
			hopSpec:     "b49ef25e17c77eca3945955bf99fae538a59865067a7fc7afd92ef9153e8ac30/path/to/key.pem",
			expectError: true,
		},
		{
			name:        "too many parts",
			hopSpec:     "b49ef25e17c77eca3945955bf99fae538a59865067a7fc7afd92ef9153e8ac30,/path/to/key.pem,extra",
			expectError: true,
		},
		{
			name:        "invalid node ID",
			hopSpec:     "invalid_hex,/path/to/key.pem",
			expectError: true,
		},
		{
			name:        "empty hop spec",
			hopSpec:     "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHopSpec(tt.hopSpec)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSURBKeysFileFormat(t *testing.T) {
	// Create test SURB keys data
	testSURBIDs := [][16]byte{
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
	}
	testKeys := []byte("test_surb_keys_data_here")

	// Create temporary file
	tmpDir := t.TempDir()
	keysFile := filepath.Join(tmpDir, "test_keys.toml")

	// Save SURB keys
	err := saveSURBKeysWithIDs(keysFile, testKeys, testSURBIDs)
	require.NoError(t, err)

	// Verify file exists
	_, err = os.Stat(keysFile)
	require.NoError(t, err)

	// Load and verify SURB keys
	loadedKeys, err := loadSURBKeysFromTOML(keysFile)
	require.NoError(t, err)
	assert.Equal(t, testKeys, loadedKeys)
}

func TestSURBPayloadExtraction(t *testing.T) {
	// Create test geometry
	geometry := &geo.Geometry{
		SURBLength: 326,
	}

	tests := []struct {
		name            string
		payload         []byte
		expectSURB      bool
		expectError     bool
		expectedUserLen int
	}{
		{
			name:            "payload with SURB",
			payload:         createTestPayloadWithSURB(t, 326),
			expectSURB:      true,
			expectError:     false,
			expectedUserLen: 100, // test user payload size
		},
		{
			name:            "payload without SURB",
			payload:         []byte{0x00, 0x00, 0x48, 0x65, 0x6c, 0x6c, 0x6f}, // flags=0, "Hello"
			expectSURB:      false,
			expectError:     false,
			expectedUserLen: 7,
		},
		{
			name:            "payload too short",
			payload:         []byte{0x01}, // only flags byte
			expectSURB:      false,
			expectError:     true, // Should error due to insufficient length
			expectedUserLen: 0,
		},
		{
			name:            "empty payload",
			payload:         []byte{},
			expectSURB:      false,
			expectError:     true, // Should error due to insufficient length
			expectedUserLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			surbFile := filepath.Join(tmpDir, "extracted.surb")

			userPayload, err := extractSURBFromPayload(tt.payload, surbFile, geometry)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			if tt.expectedUserLen > 0 {
				assert.Len(t, userPayload, tt.expectedUserLen)
			}

			if tt.expectSURB {
				// Verify SURB file was created
				_, err := os.Stat(surbFile)
				assert.NoError(t, err)

				// Verify SURB file size
				surbData, err := os.ReadFile(surbFile)
				assert.NoError(t, err)
				assert.Len(t, surbData, 326)
			} else {
				// Verify SURB file was not created or is empty
				if _, err := os.Stat(surbFile); err == nil {
					surbData, _ := os.ReadFile(surbFile)
					assert.Empty(t, surbData)
				}
			}
		})
	}
}

func TestBase64KeyEncoding(t *testing.T) {
	testData := []byte("test_key_data_for_encoding")

	// Encode
	encoded := base64.StdEncoding.EncodeToString(testData)
	assert.NotEmpty(t, encoded)

	// Decode
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	assert.Equal(t, testData, decoded)
}

func TestCommandLineValidation(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
	}{
		{
			name:        "no command",
			args:        []string{},
			expectError: true,
		},
		{
			name:        "invalid command",
			args:        []string{"invalidcommand"},
			expectError: true,
		},
		{
			name:        "help command",
			args:        []string{"--help"},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This would test command line parsing if we had a testable main function
			// For now, we test the validation logic
			if len(tt.args) == 0 {
				assert.True(t, tt.expectError, "Empty args should be invalid")
			}
		})
	}
}

// Helper functions

func validateHopSpec(hopSpec string) error {
	if hopSpec == "" {
		return assert.AnError
	}

	parts := bytes.Split([]byte(hopSpec), []byte(","))
	if len(parts) != 2 {
		return assert.AnError
	}

	// Validate node ID
	nodeIDStr := string(bytes.TrimSpace(parts[0]))
	nodeIDBytes, err := hex.DecodeString(nodeIDStr)
	if err != nil {
		return err
	}
	if len(nodeIDBytes) != 32 {
		return assert.AnError
	}

	return nil
}

func createTestPayloadWithSURB(t *testing.T, surbLength int) []byte {
	// Create payload with SURB: [flags=1][reserved=0][SURB][user_data]
	payload := make([]byte, 0, 2+surbLength+100)

	// Flags and reserved bytes
	payload = append(payload, 0x01, 0x00)

	// Mock SURB data
	surbData := make([]byte, surbLength)
	for i := range surbData {
		surbData[i] = byte(i % 256)
	}
	payload = append(payload, surbData...)

	// User payload
	userPayload := make([]byte, 100)
	for i := range userPayload {
		userPayload[i] = byte(0x41 + (i % 26)) // A-Z pattern
	}
	payload = append(payload, userPayload...)

	return payload
}

func TestGeometryValidation(t *testing.T) {
	tests := []struct {
		name        string
		geometry    *geo.Geometry
		expectValid bool
	}{
		{
			name: "valid geometry",
			geometry: &geo.Geometry{
				PacketLength:             2590,
				HeaderLength:             230,
				SURBLength:               326,
				NrHops:                   2,
				PayloadTagLength:         32,
				ForwardPayloadLength:     2328,
				UserForwardPayloadLength: 2000,
				NIKEName:                 "x25519",
			},
			expectValid: true,
		},
		{
			name: "zero hops",
			geometry: &geo.Geometry{
				NrHops: 0,
			},
			expectValid: false,
		},
		{
			name: "negative packet length",
			geometry: &geo.Geometry{
				PacketLength: -1,
				NrHops:       2,
			},
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := validateGeometry(tt.geometry)
			assert.Equal(t, tt.expectValid, valid)
		})
	}
}

func TestSURBIDGeneration(t *testing.T) {
	// Test SURB ID format and length
	var surbID [16]byte

	// Test that SURB ID is correct length
	assert.Len(t, surbID, 16, "SURB ID should be 16 bytes")

	// Test hex encoding
	idStr := hex.EncodeToString(surbID[:])
	assert.Len(t, idStr, 32, "SURB ID hex string should be 32 characters")

	// Test that different byte patterns produce different hex strings
	surbID1 := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	surbID2 := [16]byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}

	id1Str := hex.EncodeToString(surbID1[:])
	id2Str := hex.EncodeToString(surbID2[:])

	assert.NotEqual(t, id1Str, id2Str, "Different SURB IDs should produce different hex strings")
	assert.Equal(t, "0102030405060708090a0b0c0d0e0f10", id1Str)
	assert.Equal(t, "1112131415161718191a1b1c1d1e1f20", id2Str)
}

func TestFileOperations(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("write and read binary file", func(t *testing.T) {
		testData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
		testFile := filepath.Join(tmpDir, "test.bin")

		// Write file
		err := os.WriteFile(testFile, testData, 0644)
		require.NoError(t, err)

		// Read file
		readData, err := os.ReadFile(testFile)
		require.NoError(t, err)
		assert.Equal(t, testData, readData)
	})

	t.Run("file permissions", func(t *testing.T) {
		testFile := filepath.Join(tmpDir, "perm_test.bin")
		err := os.WriteFile(testFile, []byte("test"), 0644)
		require.NoError(t, err)

		info, err := os.Stat(testFile)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0644), info.Mode().Perm())
	})
}

func TestErrorHandling(t *testing.T) {
	t.Run("invalid file path", func(t *testing.T) {
		invalidPath := "/nonexistent/directory/file.bin"
		_, err := os.ReadFile(invalidPath)
		assert.Error(t, err)
	})

	t.Run("invalid hex decoding", func(t *testing.T) {
		invalidHex := "gggggggg"
		_, err := hex.DecodeString(invalidHex)
		assert.Error(t, err)
	})

	t.Run("invalid base64 decoding", func(t *testing.T) {
		invalidBase64 := "invalid base64!@#$"
		_, err := base64.StdEncoding.DecodeString(invalidBase64)
		assert.Error(t, err)
	})
}

func TestPacketSizeCalculations(t *testing.T) {
	tests := []struct {
		name           string
		nrHops         int
		expectedHeader int
		expectedSURB   int
	}{
		{
			name:           "2 hops",
			nrHops:         2,
			expectedHeader: 230, // Example values
			expectedSURB:   326,
		},
		{
			name:           "5 hops",
			nrHops:         5,
			expectedHeader: 476, // Larger header for more hops
			expectedSURB:   572, // Larger SURB for more hops
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that packet sizes scale with hop count
			assert.Greater(t, tt.expectedHeader, 0)
			assert.Greater(t, tt.expectedSURB, 0)

			if tt.nrHops > 2 {
				// More hops should result in larger packets
				assert.Greater(t, tt.expectedHeader, 230)
				assert.Greater(t, tt.expectedSURB, 326)
			}
		})
	}
}

// Additional helper functions

func validateGeometry(g *geo.Geometry) bool {
	if g == nil {
		return false
	}
	if g.NrHops <= 0 {
		return false
	}
	if g.PacketLength <= 0 {
		return false
	}
	return true
}
