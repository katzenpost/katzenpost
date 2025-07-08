// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonhole

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

const (
	// Test scheme constants
	testPKIScheme     = "Ed25519 Sphincs+"
	testLinkScheme    = "Xwing"
	testReplicaScheme = "CTIDH1024-X25519"
)

// generateRandomBoxID creates a random box ID for testing
func generateRandomBoxID(t *testing.T) *[32]byte {
	boxid := &[32]byte{}
	_, err := rand.Reader.Read(boxid[:])
	require.NoError(t, err)
	return boxid
}

// Helper function to create a test replica descriptor
func createTestReplicaDescriptor(t *testing.T, name string, pkiScheme sign.Scheme, linkScheme kem.Scheme, replicaScheme nike.Scheme) *pki.ReplicaDescriptor {
	// Generate identity key
	identityPubKey, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)
	identityKeyBytes, err := identityPubKey.MarshalBinary()
	require.NoError(t, err)

	// Generate link key
	linkPubKey, _, err := linkScheme.GenerateKeyPair()
	require.NoError(t, err)
	linkKeyBytes, err := linkPubKey.MarshalBinary()
	require.NoError(t, err)

	// Generate replica envelope key
	replicaPubKey, _, err := replicaScheme.GenerateKeyPair()
	require.NoError(t, err)
	replicaKeyBytes, err := replicaPubKey.MarshalBinary()
	require.NoError(t, err)

	// Get current replica epoch
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()

	return &pki.ReplicaDescriptor{
		Name:        name,
		IdentityKey: identityKeyBytes,
		LinkKey:     linkKeyBytes,
		Addresses: map[string][]string{
			"tcp": {"tcp://127.0.0.1:12345"},
		},
		EnvelopeKeys: map[uint64][]byte{
			replicaEpoch: replicaKeyBytes,
		},
	}
}

// Helper function to create a test PKI document with specified number of replicas
func createTestPKIDocument(t *testing.T, numReplicas int) *pki.Document {
	pkiScheme := signSchemes.ByName(testPKIScheme)
	require.NotNil(t, pkiScheme)
	linkScheme := kemSchemes.ByName(testLinkScheme)
	require.NotNil(t, linkScheme)
	replicaScheme := nikeSchemes.ByName(testReplicaScheme)
	require.NotNil(t, replicaScheme)

	replicas := make([]*pki.ReplicaDescriptor, numReplicas)
	for i := 0; i < numReplicas; i++ {
		replicas[i] = createTestReplicaDescriptor(t,
			fmt.Sprintf("replica%d", i),
			pkiScheme,
			linkScheme,
			replicaScheme)
	}

	// Create shared random value
	srv := make([]byte, 32)
	_, err := rand.Reader.Read(srv)
	require.NoError(t, err)

	currentEpoch, _, _ := epochtime.Now()

	return &pki.Document{
		Epoch:              currentEpoch,
		StorageReplicas:    replicas,
		SharedRandomValue:  srv,
		PKISignatureScheme: testPKIScheme,
	}
}

// Helper function to validate successful GetRandomIntermediateReplicas results
func validateSuccessfulResult(t *testing.T, doc *pki.Document, replicaIndices [2]uint8, replicaPubKeys []nike.PublicKey) {
	// Verify it returns 2 different replica indices
	require.Equal(t, 2, len(replicaIndices))
	require.NotEqual(t, replicaIndices[0], replicaIndices[1], "Replica indices should be different")

	// Verify indices are within valid range
	require.Less(t, replicaIndices[0], uint8(len(doc.StorageReplicas)), "First replica index should be valid")
	require.Less(t, replicaIndices[1], uint8(len(doc.StorageReplicas)), "Second replica index should be valid")

	// Verify it returns 2 public keys
	require.Equal(t, 2, len(replicaPubKeys))
	require.NotNil(t, replicaPubKeys[0], "First public key should not be nil")
	require.NotNil(t, replicaPubKeys[1], "Second public key should not be nil")

	// Verify public keys are different (by comparing their bytes)
	require.NotEqual(t, replicaPubKeys[0].Bytes(), replicaPubKeys[1].Bytes(), "Public keys should be different")

	// Verify public keys match the selected replicas
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	for i, replicaIndex := range replicaIndices {
		expectedKeyBytes := doc.StorageReplicas[replicaIndex].EnvelopeKeys[replicaEpoch]
		actualKeyBytes, err := replicaPubKeys[i].MarshalBinary()
		require.NoError(t, err)
		require.Equal(t, expectedKeyBytes, actualKeyBytes, "Public key should match replica descriptor")
	}
}

// Helper function to validate error results
func validateErrorResult(t *testing.T, replicaIndices [2]uint8, replicaPubKeys []nike.PublicKey, err error, expectedErrorSubstring string) {
	require.Error(t, err)
	require.Contains(t, err.Error(), expectedErrorSubstring)
	require.Equal(t, [2]uint8{}, replicaIndices)
	require.Nil(t, replicaPubKeys)
}

// TestGetRandomIntermediateReplicas tests the GetRandomIntermediateReplicas function
func TestGetRandomIntermediateReplicas(t *testing.T) {
	t.Run("ValidDocument", func(t *testing.T) {
		// Create a PKI document with 5 replica descriptors (need at least 4 for intermediate routing)
		doc := createTestPKIDocument(t, 5)
		boxid := generateRandomBoxID(t)

		// Call GetRandomIntermediateReplicas
		replicaIndices, replicaPubKeys, err := GetRandomIntermediateReplicas(doc, boxid)

		// Verify no errors occur
		require.NoError(t, err)

		// Validate the successful result
		validateSuccessfulResult(t, doc, replicaIndices, replicaPubKeys)
	})

	t.Run("ErrorHandling", func(t *testing.T) {
		errorTestCases := []struct {
			name                   string
			doc                    *pki.Document
			expectedErrorSubstring string
		}{
			{
				name:                   "NilDocument",
				doc:                    nil,
				expectedErrorSubstring: "PKI document is nil",
			},
			{
				name: "NilStorageReplicas",
				doc: &pki.Document{
					StorageReplicas: nil,
				},
				expectedErrorSubstring: "PKI document has nil StorageReplicas",
			},
			{
				name:                   "InsufficientReplicasForSharding",
				doc:                    createTestPKIDocument(t, 1), // 1 replica (less than required 2 for sharding)
				expectedErrorSubstring: "replica not found",         // GetShards fails first with this error
			},
			{
				name: "EmptyReplicas",
				doc: &pki.Document{
					StorageReplicas: []*pki.ReplicaDescriptor{},
				},
				expectedErrorSubstring: "doc.StorageReplicas is empty",
			},
		}

		for _, tc := range errorTestCases {
			t.Run(tc.name, func(t *testing.T) {
				boxid := generateRandomBoxID(t)
				replicaIndices, replicaPubKeys, err := GetRandomIntermediateReplicas(tc.doc, boxid)
				validateErrorResult(t, replicaIndices, replicaPubKeys, err, tc.expectedErrorSubstring)
			})
		}
	})

	t.Run("SuccessfulCases", func(t *testing.T) {
		successTestCases := []struct {
			name        string
			numReplicas int
			description string
			extraChecks func(t *testing.T, doc *pki.Document, replicaIndices [2]uint8, replicaPubKeys []nike.PublicKey)
		}{
			{
				name:        "MinimalReplicas",
				numReplicas: 2,
				description: "Test with exactly 2 replicas (minimum required)",
				extraChecks: func(t *testing.T, doc *pki.Document, replicaIndices [2]uint8, replicaPubKeys []nike.PublicKey) {
					require.Equal(t, [2]uint8{0, 1}, replicaIndices)
				},
			},
			{
				name:        "ThreeReplicas",
				numReplicas: 3,
				description: "Test with exactly 3 replicas",
				extraChecks: func(t *testing.T, doc *pki.Document, replicaIndices [2]uint8, replicaPubKeys []nike.PublicKey) {
					require.Less(t, replicaIndices[0], uint8(3))
					require.Less(t, replicaIndices[1], uint8(3))
					require.NotEqual(t, replicaIndices[0], replicaIndices[1])
				},
			},
			{
				name:        "FourReplicas",
				numReplicas: 4,
				description: "Test with exactly 4 replicas",
				extraChecks: func(t *testing.T, doc *pki.Document, replicaIndices [2]uint8, replicaPubKeys []nike.PublicKey) {
					require.Less(t, replicaIndices[0], uint8(4))
					require.Less(t, replicaIndices[1], uint8(4))
					require.NotEqual(t, replicaIndices[0], replicaIndices[1])
				},
			},
			{
				name:        "ManyReplicas",
				numReplicas: 20,
				description: "Test with many replicas to ensure indices are within bounds",
				extraChecks: func(t *testing.T, doc *pki.Document, replicaIndices [2]uint8, replicaPubKeys []nike.PublicKey) {
					require.Less(t, replicaIndices[0], uint8(20))
					require.Less(t, replicaIndices[1], uint8(20))
				},
			},
		}

		for _, tc := range successTestCases {
			t.Run(tc.name, func(t *testing.T) {
				doc := createTestPKIDocument(t, tc.numReplicas)
				boxid := generateRandomBoxID(t)
				replicaIndices, replicaPubKeys, err := GetRandomIntermediateReplicas(doc, boxid)

				require.NoError(t, err)
				validateSuccessfulResult(t, doc, replicaIndices, replicaPubKeys)

				if tc.extraChecks != nil {
					tc.extraChecks(t, doc, replicaIndices, replicaPubKeys)
				}
			})
		}
	})
}
