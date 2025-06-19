// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestReplicationVerification tests that the hash-based sharding scheme
// correctly determines which replicas should store a given Box ID.
// This test uses actual Box IDs captured from running channel tests.
func TestReplicationVerification(t *testing.T) {
	// Box ID captured from actual channel test run:
	// ALICE WRITES TO BoxID: 69cebd980c4e686b06f582597ecb611cb8ca261f3940847a43c3f0193b87f93b
	boxIDHex := "69cebd980c4e686b06f582597ecb611cb8ca261f3940847a43c3f0193b87f93b"
	boxIDBytes, err := hex.DecodeString(boxIDHex)
	require.NoError(t, err)
	require.Equal(t, 32, len(boxIDBytes))

	boxID := &[32]byte{}
	copy(boxID[:], boxIDBytes)

	t.Logf("Testing replication for Box ID: %x", boxID[:])

	// Create a test PKI document with 3 replicas (like our docker setup)
	config := createDefaultTestConfig()
	config.NumStorageReplicas = 3 // Match our docker setup
	doc := generateDocument(t, config)

	// Test GetShards - this determines which 2 replicas should store this Box ID
	shards, err := GetShards(boxID, doc)
	require.NoError(t, err)
	require.Equal(t, K, len(shards)) // K=2, so we should get 2 replicas

	t.Logf("Hash-based sharding selected %d replicas for storage:", len(shards))
	for i, shard := range shards {
		t.Logf("  Replica %d: %s (IdentityKey: %x)", i+1, shard.Name, shard.IdentityKey[:8])
	}

	// Test GetRemoteShards for each replica to see which ones should replicate
	for _, replica := range doc.StorageReplicas {
		t.Logf("\n--- Testing from perspective of %s ---", replica.Name)

		// Convert replica's identity key to PublicKey for GetRemoteShards
		replicaIdPubKey, err := config.PKIScheme.UnmarshalBinaryPublicKey(replica.IdentityKey)
		require.NoError(t, err)

		remoteShards, err := GetRemoteShards(replicaIdPubKey, boxID, doc)
		require.NoError(t, err)

		t.Logf("%s should replicate to %d remote replicas:", replica.Name, len(remoteShards))
		for j, remoteShard := range remoteShards {
			t.Logf("  Remote replica %d: %s (IdentityKey: %x)", j+1, remoteShard.Name, remoteShard.IdentityKey[:8])
		}

		// Verify that this replica is not in its own remote shards list
		for _, remoteShard := range remoteShards {
			require.NotEqual(t, replica.IdentityKey, remoteShard.IdentityKey,
				"Replica should not replicate to itself")
		}

		// Check if this replica is one of the selected shards
		isSelectedShard := false
		for _, shard := range shards {
			if string(shard.IdentityKey) == string(replica.IdentityKey) {
				isSelectedShard = true
				break
			}
		}

		if isSelectedShard {
			t.Logf("%s IS a selected shard, so it should replicate to the other selected shard", replica.Name)
			require.Equal(t, 1, len(remoteShards), "Selected shard should replicate to 1 other selected shard")
		} else {
			t.Logf("%s is NOT a selected shard, but it should still replicate to ALL selected shards", replica.Name)
			require.Equal(t, 2, len(remoteShards), "Non-selected shard should replicate to all 2 selected shards")
		}
	}
}

// TestReplicationConsistencyVerification tests that the sharding is deterministic and consistent
func TestReplicationConsistencyVerification(t *testing.T) {
	// Test with multiple Box IDs to ensure consistency
	testBoxIDs := []string{
		"69cebd980c4e686b06f582597ecb611cb8ca261f3940847a43c3f0193b87f93b", // From actual test
		"18d19c762572be8d689d8a924997f11f517acbec05e34bcc993c612c4955f012", // From previous test
		"82ba4dcca6834f55d14fa67a52c1f714b1d415baf09782f9a09f2e155335fe6e", // Bob's read BoxID
	}

	config := createDefaultTestConfig()
	config.NumStorageReplicas = 3
	doc := generateDocument(t, config)

	for _, boxIDHex := range testBoxIDs {
		boxIDBytes, err := hex.DecodeString(boxIDHex)
		require.NoError(t, err)

		boxID := &[32]byte{}
		copy(boxID[:], boxIDBytes)

		t.Logf("\n=== Testing Box ID: %x ===", boxID[:8])

		// Test that GetShards is deterministic
		shards1, err := GetShards(boxID, doc)
		require.NoError(t, err)

		shards2, err := GetShards(boxID, doc)
		require.NoError(t, err)

		require.Equal(t, shards1, shards2, "GetShards should be deterministic")
		require.Equal(t, K, len(shards1), "Should always return K shards")

		t.Logf("Shards for %x: %s, %s", boxID[:8], shards1[0].Name, shards1[1].Name)
	}
}
