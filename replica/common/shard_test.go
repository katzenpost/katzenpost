// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/kem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
)

const (
	// testPKIScheme is the PKI signature scheme used in tests
	testPKIScheme = "Ed25519 Sphincs+"
	// testLinkScheme is the link KEM scheme used in tests
	testLinkScheme = "Xwing"
	// testReplicaScheme is the replica NIKE scheme used in tests
	testReplicaScheme = "x25519"
	// testSphinxNikeScheme is the Sphinx NIKE scheme used in tests
	testSphinxNikeScheme = "x25519"
	// testNumDirAuths is the number of directory authorities in test documents
	testNumDirAuths = 9
	// testNumMixNodes is the number of mix nodes in test documents
	testNumMixNodes = 9
	// testNumStorageReplicas is the number of storage replicas in test documents
	testNumStorageReplicas = 19
)

// DocumentConfig holds configuration parameters for generating test PKI documents
type DocumentConfig struct {
	PKIScheme          sign.Scheme
	LinkScheme         kem.Scheme
	ReplicaScheme      nike.Scheme
	SphinxNikeScheme   nike.Scheme
	SphinxKemScheme    kem.Scheme
	NumDirAuths        int
	NumMixNodes        int
	NumStorageReplicas int
}

// Helper functions to eliminate code duplication

// createDefaultTestConfig creates a standard test configuration used across multiple tests
func createDefaultTestConfig() *DocumentConfig {
	return &DocumentConfig{
		PKIScheme:          signschemes.ByName(testPKIScheme),
		LinkScheme:         kemschemes.ByName(testLinkScheme),
		ReplicaScheme:      nikeschemes.ByName(testReplicaScheme),
		SphinxNikeScheme:   nikeschemes.ByName(testSphinxNikeScheme),
		SphinxKemScheme:    nil,
		NumDirAuths:        testNumDirAuths,
		NumMixNodes:        testNumMixNodes,
		NumStorageReplicas: testNumStorageReplicas,
	}
}

// generateRandomBoxID creates a random box ID for testing
func generateRandomBoxID(t *testing.T) *[32]byte {
	boxid := &[32]byte{}
	_, err := rand.Reader.Read(boxid[:])
	require.NoError(t, err)
	return boxid
}

// setupTestDocumentAndBoxID creates a test document and random box ID
func setupTestDocumentAndBoxID(t *testing.T) (*pki.Document, *[32]byte) {
	config := createDefaultTestConfig()
	doc := generateDocument(t, config)
	boxid := generateRandomBoxID(t)
	return doc, boxid
}

// generateRandomKeys creates random keys for benchmarking
func generateRandomKeys(tb testing.TB, numServers, keySize int) [][]byte {
	keys := make([][]byte, numServers)
	for i := 0; i < numServers; i++ {
		keys[i] = make([]byte, keySize)
		_, err := rand.Reader.Read(keys[i])
		require.NoError(tb, err)
	}
	return keys
}

func generateDescriptor(t *testing.T, pkiScheme sign.Scheme, linkScheme kem.Scheme, sphinxNikeScheme nike.Scheme, sphinxKemScheme kem.Scheme) *pki.MixDescriptor {
	idkey := make([]byte, pkiScheme.PublicKeySize())
	_, err := rand.Reader.Read(idkey)
	require.NoError(t, err)

	linkkey := make([]byte, linkScheme.PublicKeySize())
	_, err = rand.Reader.Read(linkkey)
	require.NoError(t, err)

	var mixkey0 []byte
	var mixkey1 []byte

	if sphinxNikeScheme == nil {
		mixkey0 = make([]byte, sphinxKemScheme.PublicKeySize())
		mixkey1 = make([]byte, sphinxKemScheme.PublicKeySize())
	} else {
		mixkey0 = make([]byte, sphinxNikeScheme.PublicKeySize())
		mixkey1 = make([]byte, sphinxNikeScheme.PublicKeySize())
	}

	_, err = rand.Reader.Read(mixkey0)
	require.NoError(t, err)
	_, err = rand.Reader.Read(mixkey1)
	require.NoError(t, err)

	return &pki.MixDescriptor{
		Name:        "fake mix node name",
		IdentityKey: idkey,
		LinkKey:     linkkey,
		MixKeys:     map[uint64][]byte{0: mixkey0, 1: mixkey1},
		Addresses:   map[string][]string{"tcp": []string{"tcp://127.0.0.1:12345"}},
	}
}

func generateReplica(t *testing.T, name string, replicaID uint8, pkiScheme sign.Scheme, linkScheme kem.Scheme, replicaScheme nike.Scheme) *pki.ReplicaDescriptor {
	pubkey, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	idkey, err := pubkey.MarshalBinary()
	require.NoError(t, err)
	_, err = rand.Reader.Read(idkey)
	require.NoError(t, err)

	linkkey := make([]byte, linkScheme.PublicKeySize())
	_, err = rand.Reader.Read(linkkey)
	require.NoError(t, err)

	replicakey := make([]byte, replicaScheme.PublicKeySize())
	_, err = rand.Reader.Read(replicakey)
	require.NoError(t, err)

	epoch, _, _ := epochtime.Now()

	return &pki.ReplicaDescriptor{
		Name:         name,
		ReplicaID:    replicaID,
		IdentityKey:  idkey,
		LinkKey:      linkkey,
		EnvelopeKeys: map[uint64][]byte{epoch: replicakey},
		Addresses:    map[string][]string{"tcp": []string{"tcp://127.0.0.1:12345"}},
	}
}

func generateDocument(t *testing.T, config *DocumentConfig) *pki.Document {
	mixNodes := make([]*pki.MixDescriptor, config.NumMixNodes)
	for i := 0; i < config.NumMixNodes; i++ {
		mixNodes[i] = generateDescriptor(t, config.PKIScheme, config.LinkScheme, config.SphinxNikeScheme, config.SphinxKemScheme)
	}
	topology := make([][]*pki.MixDescriptor, 1)
	topology[0] = mixNodes
	replicas := make([]*pki.ReplicaDescriptor, config.NumStorageReplicas)
	for i := 0; i < config.NumStorageReplicas; i++ {
		name := fmt.Sprintf("fake replica %d", i)
		replicas[i] = generateReplica(t, name, uint8(i), config.PKIScheme, config.LinkScheme, config.ReplicaScheme)
	}

	// Build ConfiguredReplicaIdentityKeys from the replicas
	configuredReplicaKeys := make([][]byte, len(replicas))
	for i, replica := range replicas {
		configuredReplicaKeys[i] = make([]byte, len(replica.IdentityKey))
		copy(configuredReplicaKeys[i], replica.IdentityKey)
	}

	srv := make([]byte, 32)
	_, err := rand.Reader.Read(srv)
	require.NoError(t, err)

	geohash := srv
	oldhashes := [][]byte{srv, srv}

	return &pki.Document{
		Topology:                      topology,
		StorageReplicas:               replicas,
		ConfiguredReplicaIdentityKeys: configuredReplicaKeys,
		SharedRandomValue:             srv,
		PriorSharedRandom:             oldhashes,
		SphinxGeometryHash:            geohash,
		PKISignatureScheme:            config.PKIScheme.Name(),
	}
}

func TestGetShards(t *testing.T) {
	doc, boxid := setupTestDocumentAndBoxID(t)

	replicaDescs, err := GetShards(boxid, doc)
	require.NoError(t, err)
	require.Equal(t, len(replicaDescs), K)
}

func TestGetConfiguredReplicaKeys(t *testing.T) {
	config := createDefaultTestConfig()
	doc := generateDocument(t, config)
	replicaKeys, err := GetConfiguredReplicaKeys(doc)
	require.NoError(t, err)
	require.Equal(t, config.NumStorageReplicas, len(replicaKeys))

	boxid := generateRandomBoxID(t)

	// Shard2 operates on full identity keys
	orderedKeys := Shard2(boxid, replicaKeys)
	for i := 0; i < len(orderedKeys); i++ {
		// Hash the identity key to look up the descriptor
		keyHash := blake2b.Sum256(orderedKeys[i])
		_, err := doc.GetReplicaNodeByKeyHash(&keyHash)
		require.NoError(t, err)
	}
}

func TestShardSimple(t *testing.T) {
	// Use deterministic test data to avoid random hash collisions
	boxid1 := &[32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}
	boxid2 := &[32]byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40}

	// Use deterministic server keys
	serverIdKeys := [][]byte{
		{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
			0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0},
		{0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
			0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0},
		{0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0,
			0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00},
		{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
			0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60},
		{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
			0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80},
	}

	shards1 := Shard2(boxid1, serverIdKeys)
	shards2 := Shard2(boxid2, serverIdKeys)

	// Verify that both calls return exactly 2 shards (K=2)
	require.Equal(t, 2, len(shards1))
	require.Equal(t, 2, len(shards2))

	// Verify that different box IDs produce different shard selections
	require.NotEqual(t, shards1, shards2)
}

func TestGetRemoteShards(t *testing.T) {
	config := createDefaultTestConfig()
	doc := generateDocument(t, config)
	boxid := generateRandomBoxID(t)

	replicaDescs, err := GetShards(boxid, doc)
	require.NoError(t, err)
	replicaIdPubKey, err := config.PKIScheme.UnmarshalBinaryPublicKey(replicaDescs[0].IdentityKey)
	require.NoError(t, err)
	replicas, err := GetRemoteShards(replicaIdPubKey, boxid, doc)
	require.NoError(t, err)
	require.Equal(t, 1, len(replicas))

	pubkey, _, err := config.PKIScheme.GenerateKey()
	require.NoError(t, err)

	replicas2, err := GetRemoteShards(pubkey, boxid, doc)
	require.NoError(t, err)
	require.Equal(t, 2, len(replicas2))
}

func TestReplicaNum(t *testing.T) {
	config := createDefaultTestConfig()
	doc := generateDocument(t, config)

	_, err := ReplicaNum(uint8(config.NumStorageReplicas-1), doc)
	require.NoError(t, err)

	_, err = ReplicaNum(uint8(config.NumStorageReplicas), doc)
	require.Error(t, err)
}

func TestShard2ConsistentHashing(t *testing.T) {
	numMessages := 1000
	keySize := 32

	for numReplicas := 4; numReplicas <= 10; numReplicas++ {
		t.Run(fmt.Sprintf("%dReplicas", numReplicas), func(t *testing.T) {
			// Generate replica keys
			keys := generateRandomKeys(t, numReplicas, keySize)

			// Generate random boxIDs (messages)
			boxIDs := make([]*[32]byte, numMessages)
			for i := 0; i < numMessages; i++ {
				boxIDs[i] = &[32]byte{}
				_, err := rand.Reader.Read(boxIDs[i][:])
				require.NoError(t, err)
			}

			// Track distribution: how many times each replica is primary (index 0) and secondary (index 1)
			primaryCount := make(map[string]int)
			secondaryCount := make(map[string]int)

			// Store original assignments for each boxID
			originalAssignments := make(map[int][2]string) // boxID index -> [primary, secondary]

			for i, boxID := range boxIDs {
				shards := Shard2(boxID, keys)
				require.Len(t, shards, K)

				primary := string(shards[0])
				secondary := string(shards[1])

				primaryCount[primary]++
				secondaryCount[secondary]++
				originalAssignments[i] = [2]string{primary, secondary}
			}

			// Verify uniform distribution for primary assignments
			expectedPerReplica := float64(numMessages) / float64(numReplicas)

			t.Logf("Expected ~%.1f messages per replica (primary)", expectedPerReplica)

			// Verify that all replicas got some assignments
			replicasWithPrimary := len(primaryCount)
			replicasWithSecondary := len(secondaryCount)
			t.Logf("Replicas with primary assignments: %d/%d", replicasWithPrimary, numReplicas)
			t.Logf("Replicas with secondary assignments: %d/%d", replicasWithSecondary, numReplicas)
			require.Equal(t, numReplicas, replicasWithPrimary, "All replicas should have primary assignments")
			require.Equal(t, numReplicas, replicasWithSecondary, "All replicas should have secondary assignments")

			// Now remove one replica and verify consistent hashing properties
			removedReplicaIdx := numReplicas / 2 // Remove replica in the middle
			removedKey := string(keys[removedReplicaIdx])

			// Create new key set without the removed replica
			newKeys := make([][]byte, 0, numReplicas-1)
			for i, key := range keys {
				if i != removedReplicaIdx {
					newKeys = append(newKeys, key)
				}
			}

			// Track changes after removal
			unchangedCount := 0
			primaryPromotedCount := 0   // secondary became primary, new secondary assigned
			secondaryReplacedCount := 0 // primary unchanged, secondary replaced
			bothChangedCount := 0       // both changed (shouldn't happen for boxes not using removed replica)

			for i, boxID := range boxIDs {
				newShards := Shard2(boxID, newKeys)
				require.Len(t, newShards, K)

				newPrimary := string(newShards[0])
				newSecondary := string(newShards[1])

				oldPrimary := originalAssignments[i][0]
				oldSecondary := originalAssignments[i][1]

				hadRemovedReplica := (oldPrimary == removedKey || oldSecondary == removedKey)

				if newPrimary == oldPrimary && newSecondary == oldSecondary {
					unchangedCount++
					require.False(t, hadRemovedReplica, "Box with removed replica should have changed")
				} else if newPrimary == oldSecondary && oldPrimary == removedKey {
					// Old primary was removed, secondary promoted to primary
					primaryPromotedCount++
					require.True(t, hadRemovedReplica)
					// Verify new secondary is different from new primary (old secondary)
					require.NotEqual(t, newSecondary, newPrimary, "New secondary should differ from promoted primary")
					require.NotEqual(t, newSecondary, removedKey, "New secondary should not be the removed replica")
				} else if newPrimary == oldPrimary && oldSecondary == removedKey {
					// Old secondary was removed, primary stays, new secondary
					secondaryReplacedCount++
					require.True(t, hadRemovedReplica)
					// Verify new secondary is different from primary and removed key
					require.NotEqual(t, newSecondary, newPrimary, "New secondary should differ from primary")
					require.NotEqual(t, newSecondary, removedKey, "New secondary should not be the removed replica")
				} else if hadRemovedReplica {
					// Some other change pattern when removed replica was involved
					bothChangedCount++
				} else {
					// This shouldn't happen - boxes not using removed replica should be unchanged
					t.Errorf("Unexpected change for box %d that didn't use removed replica: old=[%x, %x] new=[%x, %x]",
						i, oldPrimary[:8], oldSecondary[:8], newPrimary[:8], newSecondary[:8])
				}
			}

			affectedCount := primaryPromotedCount + secondaryReplacedCount + bothChangedCount
			expectedAffected := float64(numMessages) * float64(K) / float64(numReplicas) // ~K/N of messages

			t.Logf("After removing 1 of %d replicas:", numReplicas)
			t.Logf("  Unchanged: %d (%.1f%%)", unchangedCount, float64(unchangedCount)*100/float64(numMessages))
			t.Logf("  Primary promoted (old secondary->primary): %d", primaryPromotedCount)
			t.Logf("  Secondary replaced (primary intact): %d", secondaryReplacedCount)
			t.Logf("  Both changed: %d", bothChangedCount)
			t.Logf("  Total affected: %d (expected ~%.0f, which is ~%.1f%%)", affectedCount, expectedAffected, expectedAffected*100/float64(numMessages))

			// Verify that most boxes are unchanged
			// With K=2 and N replicas, we expect ~2/N to be affected
			// For N=4, that's 50%, for N=10 that's 20%
			expectedUnchangedPct := float64(numReplicas-K) / float64(numReplicas)
			minUnchanged := int(float64(numMessages) * expectedUnchangedPct * 0.8) // Allow 20% margin
			require.Greater(t, unchangedCount, minUnchanged,
				"Expected at least %.0f%% of boxes unchanged, got %.1f%%",
				expectedUnchangedPct*80, float64(unchangedCount)*100/float64(numMessages))

			// Verify affected count is roughly K/N (with some tolerance)
			maxAffected := int(expectedAffected * 1.5) // Allow 50% over expected
			require.Less(t, affectedCount, maxAffected,
				"Expected at most %.0f affected boxes, got %d", expectedAffected*1.5, affectedCount)
		})
	}
}

func BenchmarkShard2(b *testing.B) {
	numServers := 10
	keySize := 32
	keys := generateRandomKeys(b, numServers, keySize)

	boxid := &[32]byte{}
	_, err := rand.Reader.Read(boxid[:])
	require.NoError(b, err)

	var shard [][]byte
	var shard2 [][]byte
	for i := 0; i < b.N; i++ {
		shard = Shard2(boxid, keys)
	}

	shard2 = shard
	shard = shard2
}
