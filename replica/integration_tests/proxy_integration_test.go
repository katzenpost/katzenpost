// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"crypto/hmac"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/katzenpost/core/epochtime"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"

	"github.com/katzenpost/katzenpost/pigeonhole"
)

func TestProxyIntegration(t *testing.T) {
	// This test specifically verifies that proxy functionality works end-to-end
	// by deliberately sending requests to non-shard replicas using 6 replicas:
	// - Replicas 0,1: intermediary replicas for Alice's write operations
	// - Replicas 2,3: final destination replicas (determined by hash-based sharding)
	// - Replicas 4,5: intermediary replicas for Bob's read operations (proxy to 2,3)

	env := setupTestEnvironment6Replicas(t)
	// Don't defer cleanup immediately - let replicas run longer
	// But ensure cleanup happens if test fails
	var cleanupDone bool
	defer func() {
		if !cleanupDone {
			env.cleanup()
		}
	}()

	// Wait for replicas to be ready and PKI documents to be synchronized
	t.Logf("PROXY_TEST: Waiting for replicas to fully initialize...")
	time.Sleep(5 * time.Second)

	// Force all replicas to fetch PKI documents to ensure consistency
	for i, replica := range env.replicas {
		t.Logf("PROXY_TEST: Forcing PKI fetch for replica %d", i)
		err := replica.PKIWorker.ForceFetchPKI()
		require.NoError(t, err)
	}

	// Wait a bit more for PKI synchronization
	time.Sleep(2 * time.Second)

	// Generate a proper Ed25519 key pair for testing
	ed25519Scheme := ed25519.Scheme()
	publicKey, privateKey, err := ed25519Scheme.GenerateKey()
	require.NoError(t, err)

	// The BoxID must be the public key bytes
	publicKeyBytes, err := publicKey.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, 32, len(publicKeyBytes), "Ed25519 public key must be 32 bytes")

	var boxIDFromKey [32]uint8
	copy(boxIDFromKey[:], publicKeyBytes)

	// Calculate the correct shards for this BoxID
	currentEpoch, _, _ := epochtime.Now()
	doc := env.mockPKIClient.docs[currentEpoch]

	// Debug: Check how many replicas are in the PKI document
	t.Logf("PKI document has %d storage replicas", len(doc.StorageReplicas))
	for i, replica := range doc.StorageReplicas {
		t.Logf("Replica %d: Name=%s, IdentityKey=%x", i, replica.Name, replica.IdentityKey[:8])
	}

	correctShards, err := replicaCommon.GetShards(&boxIDFromKey, doc)
	require.NoError(t, err)
	require.Len(t, correctShards, 2, "Should have exactly 2 shards")

	// Find the indices of the correct shards
	var correctShardIndices [2]uint8
	shardCount := 0
	for i, replica := range doc.StorageReplicas {
		for _, shard := range correctShards {
			if hmac.Equal(replica.IdentityKey, shard.IdentityKey) {
				correctShardIndices[shardCount] = uint8(i)
				shardCount++
				break
			}
		}
	}
	require.Equal(t, 2, shardCount, "Should find both shards")

	t.Logf("BoxID %x should be stored on replicas: %d, %d",
		boxIDFromKey[:8], correctShardIndices[0], correctShardIndices[1])

	// Debug: Print the identity keys of the correct shards for comparison
	for i, shard := range correctShards {
		t.Logf("Correct shard %d: Name=%s, IdentityKey=%x", i, shard.Name, shard.IdentityKey[:8])
	}

	// Alice's write intermediaries: use replicas 0,1
	aliceIntermediaryIndices := [2]uint8{0, 1}
	t.Logf("Alice will use intermediary replicas: %d, %d for writing",
		aliceIntermediaryIndices[0], aliceIntermediaryIndices[1])

	// Bob's read intermediaries: use replicas 4,5 (these will proxy to the correct shards)
	bobIntermediaryIndices := [2]uint8{4, 5}
	t.Logf("Bob will use intermediary replicas: %d, %d for reading (will proxy to correct shards: %d, %d)",
		bobIntermediaryIndices[0], bobIntermediaryIndices[1], correctShardIndices[0], correctShardIndices[1])

	// STEP 1: Alice writes data using intermediary replicas 0,1
	writeData := []byte("test data for proxy integration")

	// Sign the payload with the private key
	signatureBytes := ed25519Scheme.Sign(privateKey, writeData, nil)
	require.Equal(t, 64, len(signatureBytes), "Ed25519 signature must be 64 bytes")

	var signature [64]uint8
	copy(signature[:], signatureBytes)

	writeRequest := &pigeonhole.ReplicaWrite{
		BoxID:      boxIDFromKey,
		Signature:  signature,
		PayloadLen: uint32(len(writeData)),
		Payload:    writeData,
	}

	writeMsg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 1, // 1 = write
		WriteMsg:    writeRequest,
	}

	// Create MKEM envelope using Alice's intermediary replicas (0,1)
	t.Logf("PROXY_TEST: Creating write envelope using Alice's intermediaries: %v", aliceIntermediaryIndices)
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	var aliceReplicaPubKeys []nike.PublicKey

	for _, replicaIndex := range aliceIntermediaryIndices {
		pubKey := env.replicaKeys[replicaIndex][replicaEpoch]
		aliceReplicaPubKeys = append(aliceReplicaPubKeys, pubKey)
	}

	aliceMkemPrivateKey, aliceMkemCiphertext := mkemNikeScheme.Encapsulate(aliceReplicaPubKeys, writeMsg.Bytes())
	aliceMkemPublicKey := aliceMkemPrivateKey.Public()
	aliceSenderPubkeyBytes := aliceMkemPublicKey.Bytes()

	writeEnvelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: aliceIntermediaryIndices,
		Dek1:                 *aliceMkemCiphertext.DEKCiphertexts[0],
		Dek2:                 *aliceMkemCiphertext.DEKCiphertexts[1],
		ReplyIndex:           0,
		Epoch:                replicaEpoch,
		SenderPubkeyLen:      uint16(len(aliceSenderPubkeyBytes)),
		SenderPubkey:         aliceSenderPubkeyBytes,
		CiphertextLen:        uint32(len(aliceMkemCiphertext.Envelope)),
		Ciphertext:           aliceMkemCiphertext.Envelope,
	}

	t.Logf("PROXY_TEST: Write envelope created, injecting to courier")
	writeReply := injectCourierEnvelope(t, env, writeEnvelope)
	require.NotNil(t, writeReply)

	t.Logf("PROXY_TEST: Write completed using Alice's intermediaries: %v", aliceIntermediaryIndices)

	// Wait for write and replication to complete
	t.Logf("PROXY_TEST: Waiting for replication to complete...")
	time.Sleep(10 * time.Second)

	// STEP 2: Bob reads data using intermediary replicas 4,5 (which will proxy to correct shards)
	t.Logf("PROXY_TEST: Creating read request for BoxID %x using Bob's intermediaries: %v", boxIDFromKey, bobIntermediaryIndices)
	readRequest := &pigeonhole.ReplicaRead{
		BoxID: boxIDFromKey,
	}

	readMsg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 0, // 0 = read
		ReadMsg:     readRequest,
	}

	// Create MKEM envelope using Bob's intermediary replicas (4,5)
	t.Logf("PROXY_TEST: Creating read envelope with Bob's intermediaries to force proxy: %v", bobIntermediaryIndices)
	var bobReplicaPubKeys []nike.PublicKey

	for _, replicaIndex := range bobIntermediaryIndices {
		pubKey := env.replicaKeys[replicaIndex][replicaEpoch]
		bobReplicaPubKeys = append(bobReplicaPubKeys, pubKey)
	}

	bobMkemPrivateKey, bobMkemCiphertext := mkemNikeScheme.Encapsulate(bobReplicaPubKeys, readMsg.Bytes())
	bobMkemPublicKey := bobMkemPrivateKey.Public()
	bobSenderPubkeyBytes := bobMkemPublicKey.Bytes()

	proxyReadEnvelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: bobIntermediaryIndices, // Using Bob's intermediaries (will proxy)!
		Dek1:                 *bobMkemCiphertext.DEKCiphertexts[0],
		Dek2:                 *bobMkemCiphertext.DEKCiphertexts[1],
		ReplyIndex:           0,
		Epoch:                replicaEpoch,
		SenderPubkeyLen:      uint16(len(bobSenderPubkeyBytes)),
		SenderPubkey:         bobSenderPubkeyBytes,
		CiphertextLen:        uint32(len(bobMkemCiphertext.Envelope)),
		Ciphertext:           bobMkemCiphertext.Envelope,
	}

	t.Logf("PROXY_TEST: Sending read request to Bob's intermediaries: %v (should trigger proxy to correct shards: %v)",
		bobIntermediaryIndices, correctShardIndices)

	// Send proxy read request
	t.Logf("PROXY_TEST: Read envelope created, injecting to courier")
	proxyReadReply := injectCourierEnvelope(t, env, proxyReadEnvelope)
	require.NotNil(t, proxyReadReply, "Courier should return a reply")

	// If we didn't get a payload immediately, wait for the proxy operation to complete
	if len(proxyReadReply.Payload) == 0 {
		t.Logf("PROXY_TEST: No immediate payload, waiting for proxy operation to complete...")
		proxyReadReply = waitForReplicaResponse(t, env, proxyReadEnvelope)
		require.NotNil(t, proxyReadReply, "Should receive proxy response after waiting")
	}

	// Test must fail if no payload is received
	require.Greater(t, len(proxyReadReply.Payload), 0, "Proxy read must return a payload - proxy functionality failed")

	t.Logf("SUCCESS: Received proxy reply with payload length: %d", len(proxyReadReply.Payload))

	// Decrypt and verify the response
	replicaIndex := int(bobIntermediaryIndices[proxyReadReply.ReplyIndex])
	replicaPubKey := env.replicaKeys[replicaIndex][replicaEpoch]
	rawInnerMsg, err := mkemNikeScheme.DecryptEnvelope(bobMkemPrivateKey, replicaPubKey, proxyReadReply.Payload)
	require.NoError(t, err, "Failed to decrypt proxy reply")

	innerMsg, err := pigeonhole.ParseReplicaMessageReplyInnerMessage(rawInnerMsg)
	require.NoError(t, err, "Failed to parse replica message reply")
	require.NotNil(t, innerMsg.ReadReply, "ReadReply should not be nil")

	// Test must fail if the operation was not successful
	require.Equal(t, pigeonhole.ReplicaSuccess, innerMsg.ReadReply.ErrorCode,
		"Proxy read must succeed - error code: %d", innerMsg.ReadReply.ErrorCode)

	// Test must fail if the data doesn't match
	require.Equal(t, writeData, innerMsg.ReadReply.Payload,
		"Retrieved data must match written data - proxy functionality failed")

	t.Logf("SUCCESS: Proxy read succeeded! Retrieved data: %s", string(innerMsg.ReadReply.Payload))

	// Wait longer to ensure all proxy operations and connections are properly cleaned up
	t.Logf("PROXY_TEST: Waiting for all operations to complete before cleanup...")
	time.Sleep(15 * time.Second)

	// Now cleanup the environment
	cleanupDone = true
	env.cleanup()
}

// setupTestEnvironment6Replicas creates a test environment with 6 replicas for proxy testing
func setupTestEnvironment6Replicas(t *testing.T) *testEnvironment {
	// We need 6 replicas for the proxy integration test with specific allocation:
	// - Replicas 0,1: Alice's write intermediaries
	// - Replicas 2,3: Final destination replicas (determined by sharding)
	// - Replicas 4,5: Bob's read intermediaries (will proxy to 2,3)
	return setupTestEnvironmentWithReplicas(t, 6, "courier_replica_proxy_test_*")
}
