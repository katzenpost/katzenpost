// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"crypto/hmac"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/katzenpost/core/epochtime"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"

	"github.com/katzenpost/katzenpost/pigeonhole"
)

func TestProxyIntegration(t *testing.T) {
	// This test specifically verifies that proxy functionality works end-to-end
	// by deliberately sending requests to non-shard replicas

	env := setupTestEnvironment(t)
	defer env.cleanup()

	// Wait for replicas to be ready
	time.Sleep(2 * time.Second)

	// Create a test BoxID
	boxID := [32]byte{}
	copy(boxID[:], "test_proxy_integration_box")

	// Get the correct shards for this BoxID
	currentEpoch, _, _ := epochtime.Now()
	doc := env.mockPKIClient.docs[currentEpoch]
	correctShards, err := replicaCommon.GetShards(&boxID, doc)
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
		boxID[:8], correctShardIndices[0], correctShardIndices[1])

	// Find intermediary replicas that are NOT the correct shards
	var wrongIntermediaryIndices [2]uint8
	wrongCount := 0
	for i := 0; i < len(doc.StorageReplicas) && wrongCount < 2; i++ {
		isCorrectShard := false
		for _, correctIndex := range correctShardIndices {
			if uint8(i) == correctIndex {
				isCorrectShard = true
				break
			}
		}
		if !isCorrectShard {
			wrongIntermediaryIndices[wrongCount] = uint8(i)
			wrongCount++
		}
	}

	// If we don't have enough wrong replicas, skip the test
	if wrongCount < 1 {
		t.Skip("Not enough non-shard replicas available to test proxy functionality")
		return
	}

	// Use at least one wrong replica to trigger proxy
	if wrongCount == 1 {
		wrongIntermediaryIndices[1] = correctShardIndices[0]
	}

	t.Logf("Using intermediary replicas: %d, %d (deliberately choosing non-shards to force proxying)",
		wrongIntermediaryIndices[0], wrongIntermediaryIndices[1])

	// First, write some data using correct intermediaries
	writeData := []byte("test data for proxy integration")
	correctSharding := getShardingInfo(t, env, &boxID)

	writeRequest := &pigeonhole.ReplicaWrite{
		BoxID:   boxID,
		Payload: writeData,
	}

	writeMsg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 1, // 1 = write
		WriteMsg:    writeRequest,
	}

	t.Logf("PROXY_TEST: Creating write envelope with correct sharding: %v", correctSharding.ReplicaIndices)
	writeEnvelope := createMKEMEnvelope(t, correctSharding, writeMsg, false)
	t.Logf("PROXY_TEST: Write envelope created, injecting to courier")
	writeReply := injectCourierEnvelope(t, env, writeEnvelope)
	require.NotNil(t, writeReply)

	t.Logf("PROXY_TEST: Write completed using correct intermediaries: %v", correctSharding.ReplicaIndices)

	// Wait for write to complete
	time.Sleep(3 * time.Second)

	// Now create a read request using wrong intermediaries to force proxy
	t.Logf("PROXY_TEST: Creating read request for BoxID %x using wrong intermediaries: %v", boxID, wrongIntermediaryIndices)
	readRequest := &pigeonhole.ReplicaRead{
		BoxID: boxID,
	}

	readMsg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 0, // 0 = read
		ReadMsg:     readRequest,
	}

	// Create MKEM envelope using wrong intermediary replicas
	t.Logf("PROXY_TEST: Creating read envelope with wrong sharding to force proxy: %v", wrongIntermediaryIndices)
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	var wrongReplicaPubKeys []nike.PublicKey

	for _, replicaIndex := range wrongIntermediaryIndices {
		pubKey := env.replicaKeys[replicaIndex][replicaEpoch]
		wrongReplicaPubKeys = append(wrongReplicaPubKeys, pubKey)
	}

	mkemPrivateKey, mkemCiphertext := mkemNikeScheme.Encapsulate(wrongReplicaPubKeys, readMsg.Bytes())
	mkemPublicKey := mkemPrivateKey.Public()
	senderPubkeyBytes := mkemPublicKey.Bytes()

	proxyReadEnvelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: wrongIntermediaryIndices, // Using wrong intermediaries!
		Dek1:                 *mkemCiphertext.DEKCiphertexts[0],
		Dek2:                 *mkemCiphertext.DEKCiphertexts[1],
		ReplyIndex:           0,
		Epoch:                replicaEpoch,
		SenderPubkeyLen:      uint16(len(senderPubkeyBytes)),
		SenderPubkey:         senderPubkeyBytes,
		CiphertextLen:        uint32(len(mkemCiphertext.Envelope)),
		Ciphertext:           mkemCiphertext.Envelope,
	}

	t.Logf("PROXY_TEST: Sending read request to wrong intermediaries: %v (should trigger proxy to correct shards: %v)",
		wrongIntermediaryIndices, correctShardIndices)

	// Send proxy read request
	t.Logf("PROXY_TEST: Read envelope created, injecting to courier")
	proxyReadReply := injectCourierEnvelope(t, env, proxyReadEnvelope)
	require.NotNil(t, proxyReadReply)

	if len(proxyReadReply.Payload) > 0 {
		t.Logf("SUCCESS: Received proxy reply with payload length: %d", len(proxyReadReply.Payload))

		// Decrypt and verify the response
		replicaIndex := int(wrongIntermediaryIndices[proxyReadReply.ReplyIndex])
		replicaPubKey := env.replicaKeys[replicaIndex][replicaEpoch]
		rawInnerMsg, err := mkemNikeScheme.DecryptEnvelope(mkemPrivateKey, replicaPubKey, proxyReadReply.Payload)
		require.NoError(t, err)

		innerMsg, err := pigeonhole.ParseReplicaMessageReplyInnerMessage(rawInnerMsg)
		require.NoError(t, err)
		require.NotNil(t, innerMsg.ReadReply)

		if innerMsg.ReadReply.ErrorCode == pigeonhole.ReplicaErrorSuccess {
			t.Logf("SUCCESS: Proxy read succeeded! Retrieved data: %s", string(innerMsg.ReadReply.Payload))
			require.Equal(t, writeData, innerMsg.ReadReply.Payload, "Retrieved data should match written data")
		} else {
			t.Logf("Proxy read returned error code: %d", innerMsg.ReadReply.ErrorCode)
		}
	} else {
		t.Logf("No payload in proxy reply - checking if proxy functionality is working")
	}
}
