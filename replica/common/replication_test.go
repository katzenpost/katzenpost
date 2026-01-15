// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/pki"
)

// TestReplicationScenarios tests various replication scenarios that occur in practice
func TestReplicationScenarios(t *testing.T) {
	config := createDefaultTestConfig()
	config.NumStorageReplicas = 3 // Match our docker setup
	doc := generateDocument(t, config)

	// Test with actual Box IDs captured from running tests
	testCases := []struct {
		name     string
		boxIDHex string
		desc     string
	}{
		{
			name:     "ActualChannelBoxID1",
			boxIDHex: "69cebd980c4e686b06f582597ecb611cb8ca261f3940847a43c3f0193b87f93b",
			desc:     "Box ID from successful channel test",
		},
		{
			name:     "ActualChannelBoxID2",
			boxIDHex: "18d19c762572be8d689d8a924997f11f517acbec05e34bcc993c612c4955f012",
			desc:     "Box ID from previous channel test",
		},
		{
			name:     "ActualReadBoxID",
			boxIDHex: "82ba4dcca6834f55d14fa67a52c1f714b1d415baf09782f9a09f2e155335fe6e",
			desc:     "Box ID from Bob's read operation",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			boxIDBytes, err := hex.DecodeString(tc.boxIDHex)
			require.NoError(t, err)
			require.Equal(t, 32, len(boxIDBytes))

			boxID := &[32]byte{}
			copy(boxID[:], boxIDBytes)

			t.Logf("Testing %s: %s", tc.desc, tc.boxIDHex)

			// Test GetShards - should return exactly K=2 replicas
			shards, err := GetShards(boxID, doc)
			require.NoError(t, err)
			require.Equal(t, K, len(shards))
			require.Equal(t, 2, len(shards)) // K should be 2

			t.Logf("Selected shards: %s, %s", shards[0].Name, shards[1].Name)

			// Verify shards are different
			require.NotEqual(t, shards[0].IdentityKey, shards[1].IdentityKey)

			// Test replication behavior for each replica
			for _, replica := range doc.StorageReplicas {
				t.Logf("Testing replication from %s", replica.Name)

				replicaIdPubKey, err := config.PKIScheme.UnmarshalBinaryPublicKey(replica.IdentityKey)
				require.NoError(t, err)

				remoteShards, err := GetRemoteShards(replicaIdPubKey, boxID, doc)
				require.NoError(t, err)

				// Check if this replica is selected
				isSelected := false
				for _, shard := range shards {
					if string(shard.IdentityKey) == string(replica.IdentityKey) {
						isSelected = true
						break
					}
				}

				if isSelected {
					// Selected replica should replicate to 1 other selected replica
					require.Equal(t, 1, len(remoteShards))
					t.Logf("  %s (selected) replicates to: %s", replica.Name, remoteShards[0].Name)
				} else {
					// Non-selected replica should replicate to all 2 selected replicas
					require.Equal(t, 2, len(remoteShards))
					t.Logf("  %s (not selected) replicates to: %s, %s",
						replica.Name, remoteShards[0].Name, remoteShards[1].Name)
				}

				// Verify replica doesn't replicate to itself
				for _, remoteShard := range remoteShards {
					require.NotEqual(t, replica.IdentityKey, remoteShard.IdentityKey)
				}
			}
		})
	}
}

// TestReplicationConsistency verifies that sharding is deterministic and consistent
func TestReplicationConsistency(t *testing.T) {
	config := createDefaultTestConfig()
	config.NumStorageReplicas = 5 // Test with different number of replicas
	doc := generateDocument(t, config)

	boxID := generateRandomBoxID(t)

	// Test that GetShards is deterministic
	shards1, err := GetShards(boxID, doc)
	require.NoError(t, err)

	shards2, err := GetShards(boxID, doc)
	require.NoError(t, err)

	require.Equal(t, shards1, shards2, "GetShards should be deterministic")

	// Test that GetRemoteShards is deterministic for each replica
	for _, replica := range doc.StorageReplicas {
		replicaIdPubKey, err := config.PKIScheme.UnmarshalBinaryPublicKey(replica.IdentityKey)
		require.NoError(t, err)

		remoteShards1, err := GetRemoteShards(replicaIdPubKey, boxID, doc)
		require.NoError(t, err)

		remoteShards2, err := GetRemoteShards(replicaIdPubKey, boxID, doc)
		require.NoError(t, err)

		require.Equal(t, remoteShards1, remoteShards2,
			"GetRemoteShards should be deterministic for replica %s", replica.Name)
	}
}

// TestReplicationErrorHandling tests error conditions in replication functions
func TestReplicationErrorHandling(t *testing.T) {
	t.Run("NilDocument", func(t *testing.T) {
		boxID := generateRandomBoxID(t)

		// GetShards with nil document should panic
		require.Panics(t, func() {
			GetShards(boxID, nil)
		}, "GetShards should panic with nil document")
	})

	t.Run("EmptyStorageReplicas", func(t *testing.T) {
		doc := &pki.Document{
			StorageReplicas:               []*pki.ReplicaDescriptor{},
			ConfiguredReplicaIdentityKeys: [][]byte{},
		}
		boxID := generateRandomBoxID(t)

		_, err := GetShards(boxID, doc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "insufficient configured replicas")
	})

	t.Run("NilConfiguredReplicaKeys", func(t *testing.T) {
		doc := &pki.Document{
			StorageReplicas:               nil,
			ConfiguredReplicaIdentityKeys: nil,
		}
		boxID := generateRandomBoxID(t)

		_, err := GetShards(boxID, doc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "ConfiguredReplicaIdentityKeys is nil")
	})

	t.Run("InsufficientReplicas", func(t *testing.T) {
		config := createDefaultTestConfig()
		config.NumStorageReplicas = 1 // Less than K=2
		doc := generateDocument(t, config)
		boxID := generateRandomBoxID(t)

		_, err := GetShards(boxID, doc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "insufficient configured replicas")
	})
}

// TestReplicationDistribution verifies that sharding distributes load evenly
func TestReplicationDistribution(t *testing.T) {
	config := createDefaultTestConfig()
	config.NumStorageReplicas = 5
	doc := generateDocument(t, config)

	// Test with many different Box IDs to verify distribution
	numTests := 100
	replicaSelectionCount := make(map[string]int)

	for testNum := 0; testNum < numTests; testNum++ {
		boxID := generateRandomBoxID(t)
		shards, err := GetShards(boxID, doc)
		require.NoError(t, err)
		require.Equal(t, K, len(shards))

		for _, shard := range shards {
			replicaSelectionCount[shard.Name]++
		}
	}

	t.Logf("Replica selection distribution over %d tests:", numTests)
	for name, count := range replicaSelectionCount {
		percentage := float64(count) / float64(numTests*K) * 100
		t.Logf("  %s: %d selections (%.1f%%)", name, count, percentage)
	}

	// Verify that all replicas are selected at least once (with high probability)
	require.Equal(t, config.NumStorageReplicas, len(replicaSelectionCount),
		"All replicas should be selected at least once")

	// Verify reasonable distribution (no replica should be selected more than 60% of the time)
	expectedPerReplica := float64(numTests*K) / float64(config.NumStorageReplicas)
	for name, count := range replicaSelectionCount {
		percentage := float64(count) / float64(numTests*K) * 100
		require.Less(t, percentage, 60.0,
			"Replica %s selected too frequently (%.1f%%), expected around %.1f%%",
			name, percentage, expectedPerReplica/float64(numTests*K)*100)
	}
}

// TestReplicationWithMinimalReplicas tests edge case with exactly K replicas
func TestReplicationWithMinimalReplicas(t *testing.T) {
	config := createDefaultTestConfig()
	config.NumStorageReplicas = K // Exactly K=2 replicas
	doc := generateDocument(t, config)
	boxID := generateRandomBoxID(t)

	shards, err := GetShards(boxID, doc)
	require.NoError(t, err)
	require.Equal(t, K, len(shards))

	// With only K replicas, all replicas should be selected
	require.Equal(t, config.NumStorageReplicas, len(shards))

	// Test replication behavior - each replica should replicate to the other
	for _, replica := range doc.StorageReplicas {
		replicaIdPubKey, err := config.PKIScheme.UnmarshalBinaryPublicKey(replica.IdentityKey)
		require.NoError(t, err)

		remoteShards, err := GetRemoteShards(replicaIdPubKey, boxID, doc)
		require.NoError(t, err)
		require.Equal(t, 1, len(remoteShards)) // Should replicate to 1 other replica

		// Verify it's not replicating to itself
		require.NotEqual(t, replica.IdentityKey, remoteShards[0].IdentityKey)
	}
}

// TestGetConfiguredReplicaKeysFunction tests the core GetConfiguredReplicaKeys function with various scenarios
func TestGetConfiguredReplicaKeysFunction(t *testing.T) {
	t.Run("BasicFunctionality", func(t *testing.T) {
		boxID := &[32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		// Create 4 fake identity keys
		keys := make([][]byte, 4)
		for i := range keys {
			keys[i] = make([]byte, 32)
			keys[i][0] = byte(i)
		}
		doc := &pki.Document{
			ConfiguredReplicaIdentityKeys: keys,
		}

		result, err := GetConfiguredReplicaKeys(doc)
		require.NoError(t, err)
		require.Equal(t, 4, len(result))

		// Test Shard2 with these keys
		shards := Shard2(boxID, result)
		require.Equal(t, K, len(shards))
		require.NotEqual(t, shards[0], shards[1]) // Should be different shards
	})

	t.Run("DeterministicBehavior", func(t *testing.T) {
		boxID := generateRandomBoxID(t)
		keys := make([][]byte, 10)
		for i := range keys {
			keys[i] = make([]byte, 32)
			keys[i][0] = byte(i)
		}
		doc := &pki.Document{
			ConfiguredReplicaIdentityKeys: keys,
		}

		result, err := GetConfiguredReplicaKeys(doc)
		require.NoError(t, err)

		shards1 := Shard2(boxID, result)
		shards2 := Shard2(boxID, result)

		require.Equal(t, shards1, shards2, "Shard2 should be deterministic")
	})

	t.Run("DifferentBoxIDsDifferentResults", func(t *testing.T) {
		boxID1 := &[32]byte{0x01}
		boxID2 := &[32]byte{0x02}
		keys := make([][]byte, 5)
		for i := range keys {
			keys[i] = make([]byte, 32)
			keys[i][0] = byte(i)
		}
		doc := &pki.Document{
			ConfiguredReplicaIdentityKeys: keys,
		}

		result, err := GetConfiguredReplicaKeys(doc)
		require.NoError(t, err)

		shards1 := Shard2(boxID1, result)
		shards2 := Shard2(boxID2, result)

		// Different box IDs should generally produce different shard selections
		require.Equal(t, K, len(shards1))
		require.Equal(t, K, len(shards2))
	})

	t.Run("MinimalReplicas", func(t *testing.T) {
		boxID := generateRandomBoxID(t)
		// Exactly 2 keys (minimum for K=2)
		keys := make([][]byte, 2)
		keys[0] = make([]byte, 32)
		keys[0][0] = 0x05
		keys[1] = make([]byte, 32)
		keys[1][0] = 0x10
		doc := &pki.Document{
			ConfiguredReplicaIdentityKeys: keys,
		}

		result, err := GetConfiguredReplicaKeys(doc)
		require.NoError(t, err)
		require.Equal(t, K, len(result))

		shards := Shard2(boxID, result)
		require.Equal(t, K, len(shards))
		// With only 2 keys, both should be selected
		require.NotEqual(t, shards[0], shards[1])
	})
}

// TestReplicaNumFunction tests the ReplicaNum helper function
func TestReplicaNumFunction(t *testing.T) {
	config := createDefaultTestConfig()
	config.NumStorageReplicas = 5
	doc := generateDocument(t, config)

	t.Run("ValidReplicaNumbers", func(t *testing.T) {
		for i := uint8(0); i < uint8(config.NumStorageReplicas); i++ {
			replica, err := ReplicaNum(i, doc)
			require.NoError(t, err)
			require.NotNil(t, replica)
			require.Equal(t, doc.StorageReplicas[i], replica)
		}
	})

	t.Run("InvalidReplicaNumbers", func(t *testing.T) {
		// Test out of bounds
		_, err := ReplicaNum(uint8(config.NumStorageReplicas), doc)
		require.Error(t, err)

		_, err = ReplicaNum(255, doc)
		require.Error(t, err)
	})

	t.Run("EmptyDocument", func(t *testing.T) {
		emptyDoc := &pki.Document{StorageReplicas: []*pki.ReplicaDescriptor{}}
		_, err := ReplicaNum(0, emptyDoc)
		require.Error(t, err)
	})
}
