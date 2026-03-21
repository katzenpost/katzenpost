// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client2/constants"
	"github.com/katzenpost/katzenpost/core/epochtime"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"

	"github.com/katzenpost/katzenpost/pigeonhole"
)

func TestProxyIntegration(t *testing.T) {
	// This test verifies proxy functionality works end-to-end using BACAP encryption.
	// It writes data to correct shard replicas, then reads via non-shard replicas
	// (forcing proxy behavior) and verifies the data is correctly retrieved.

	env := setupTestEnvironment6Replicas(t)
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
	time.Sleep(2 * time.Second)

	// --- Setup BACAP: Alice creates a write capability and gives Bob a read capability ---
	aliceOwner, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	aliceStatefulWriter, err := bacap.NewStatefulWriter(aliceOwner, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)
	bobReadCap := aliceOwner.ReadCap()
	bobStatefulReader, err := bacap.NewStatefulReader(bobReadCap, constants.PIGEONHOLE_CTX)
	require.NoError(t, err)

	// --- STEP 1: Alice writes data using BACAP encryption to correct shard replicas ---
	writeData := []byte("test data for proxy integration")

	// Create padded payload with length prefix for BACAP
	paddedPayload, err := pigeonhole.CreatePaddedPayload(writeData, env.geometry.MaxPlaintextPayloadLength+4)
	require.NoError(t, err)

	// Encrypt with BACAP - this produces the correct ciphertext size
	boxID, ciphertext, sigraw, err := aliceStatefulWriter.EncryptNext(paddedPayload)
	require.NoError(t, err)

	t.Logf("PROXY_TEST: Alice writes to BoxID: %x", boxID[:8])

	sig := [bacap.SignatureSize]byte{}
	copy(sig[:], sigraw)

	writeRequest := pigeonhole.ReplicaWrite{
		BoxID:      boxID,
		Signature:  sig,
		PayloadLen: uint32(len(ciphertext)),
		Payload:    ciphertext,
	}
	writeMsg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 1, // 1 = write
		WriteMsg:    &writeRequest,
	}

	// Use proper sharding to determine which replicas should store this BoxID
	sharding := getShardingInfo(t, env, &boxID)
	t.Logf("PROXY_TEST: BoxID will be written to correct shard replicas: %d, %d",
		sharding.ReplicaIndices[0], sharding.ReplicaIndices[1])

	replicaEpoch, _, _ := replicaCommon.ReplicaNow()

	// Create MKEM envelope for the write operation to correct shards
	mkemPrivateKey, mkemCiphertext := mkemNikeScheme.Encapsulate(sharding.ReplicaPubKeys, writeMsg.Bytes())
	mkemPublicKey := mkemPrivateKey.Public()
	senderPubkeyBytes := mkemPublicKey.Bytes()

	writeEnvelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: sharding.ReplicaIndices,
		Dek1:                 *mkemCiphertext.DEKCiphertexts[0],
		Dek2:                 *mkemCiphertext.DEKCiphertexts[1],
		ReplyIndex:           0,
		Epoch:                replicaEpoch,
		SenderPubkeyLen:      uint16(len(senderPubkeyBytes)),
		SenderPubkey:         senderPubkeyBytes,
		CiphertextLen:        uint32(len(mkemCiphertext.Envelope)),
		Ciphertext:           mkemCiphertext.Envelope,
	}

	t.Logf("PROXY_TEST: Write envelope created, injecting to courier")
	writeReply := injectCourierEnvelope(t, env, writeEnvelope)
	require.NotNil(t, writeReply)
	t.Logf("PROXY_TEST: Write completed to correct shards")

	// Wait for write to complete
	time.Sleep(5 * time.Second)

	// --- STEP 2: Bob reads via NON-shard replicas (forcing proxy behavior) ---
	// Find two replicas that are NOT the correct shards
	var bobIntermediaryIndices [2]uint8
	var bobReplicaPubKeys []nike.PublicKey = make([]nike.PublicKey, 2)
	nonShardCount := 0

	currentEpoch, _, _ := epochtime.Now()
	doc := env.mockPKIClient.docs[currentEpoch]

	for i := 0; i < len(doc.StorageReplicas) && nonShardCount < 2; i++ {
		isShard := false
		for _, shardIdx := range sharding.ReplicaIndices {
			if uint8(i) == shardIdx {
				isShard = true
				break
			}
		}
		if !isShard {
			bobIntermediaryIndices[nonShardCount] = uint8(i)
			pubKey, err := replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(
				doc.StorageReplicas[i].EnvelopeKeys[replicaEpoch])
			require.NoError(t, err)
			bobReplicaPubKeys[nonShardCount] = pubKey
			nonShardCount++
		}
	}
	require.Equal(t, 2, nonShardCount, "Should find at least 2 non-shard replicas")

	t.Logf("PROXY_TEST: Bob will read via non-shard replicas: %d, %d (will proxy to correct shards: %d, %d)",
		bobIntermediaryIndices[0], bobIntermediaryIndices[1],
		sharding.ReplicaIndices[0], sharding.ReplicaIndices[1])

	// Get the BoxID Bob expects to read (same as what Alice wrote)
	expectedBoxID, err := bobStatefulReader.NextBoxID()
	require.NoError(t, err)
	t.Logf("PROXY_TEST: Bob reads from BoxID: %x", expectedBoxID[:8])

	readRequest := &pigeonhole.ReplicaRead{
		BoxID: *expectedBoxID,
	}
	readMsg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 0, // 0 = read
		ReadMsg:     readRequest,
	}

	// Create MKEM envelope for read - but target NON-shard replicas to force proxying
	bobMkemPrivateKey, bobMkemCiphertext := mkemNikeScheme.Encapsulate(bobReplicaPubKeys, readMsg.Bytes())
	bobMkemPublicKey := bobMkemPrivateKey.Public()
	bobSenderPubkeyBytes := bobMkemPublicKey.Bytes()

	proxyReadEnvelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: bobIntermediaryIndices, // Non-shard replicas - will proxy!
		Dek1:                 *bobMkemCiphertext.DEKCiphertexts[0],
		Dek2:                 *bobMkemCiphertext.DEKCiphertexts[1],
		ReplyIndex:           0,
		Epoch:                replicaEpoch,
		SenderPubkeyLen:      uint16(len(bobSenderPubkeyBytes)),
		SenderPubkey:         bobSenderPubkeyBytes,
		CiphertextLen:        uint32(len(bobMkemCiphertext.Envelope)),
		Ciphertext:           bobMkemCiphertext.Envelope,
	}

	t.Logf("PROXY_TEST: Read envelope created, injecting to courier")
	proxyReadReply := injectCourierEnvelope(t, env, proxyReadEnvelope)
	require.NotNil(t, proxyReadReply, "Courier should return a reply")

	// If we didn't get a payload immediately, wait for the proxy operation to complete
	if len(proxyReadReply.Payload) == 0 {
		t.Logf("PROXY_TEST: No immediate payload, waiting for proxy operation to complete...")
		proxyReadReply = waitForReplicaResponse(t, env, proxyReadEnvelope)
		require.NotNil(t, proxyReadReply, "Should receive proxy response after waiting")
	}

	require.Greater(t, len(proxyReadReply.Payload), 0, "Proxy read must return a payload")
	t.Logf("PROXY_TEST: Received proxy reply with payload length: %d", len(proxyReadReply.Payload))

	// Decrypt the MKEM envelope to get the inner message
	replicaIndex := int(bobIntermediaryIndices[proxyReadReply.ReplyIndex])
	replicaPubKey := env.replicaKeys[replicaIndex][replicaEpoch]
	rawInnerMsg, err := mkemNikeScheme.DecryptEnvelope(bobMkemPrivateKey, replicaPubKey, proxyReadReply.Payload)
	require.NoError(t, err, "Failed to decrypt proxy reply")

	innerMsg, err := pigeonhole.ParseReplicaMessageReplyInnerMessage(rawInnerMsg)
	require.NoError(t, err, "Failed to parse replica message reply")
	require.NotNil(t, innerMsg.ReadReply, "ReadReply should not be nil")
	require.Equal(t, pigeonhole.ReplicaSuccess, innerMsg.ReadReply.ErrorCode,
		"Proxy read must succeed - error code: %d", innerMsg.ReadReply.ErrorCode)

	// Decrypt the BACAP payload using Bob's StatefulReader
	var signature [64]byte
	copy(signature[:], innerMsg.ReadReply.Signature[:])
	bobPaddedPlaintext, err := bobStatefulReader.DecryptNext(
		constants.PIGEONHOLE_CTX, *expectedBoxID, innerMsg.ReadReply.Payload, signature)
	require.NoError(t, err, "Failed to decrypt BACAP payload")

	// Extract the actual message data from the padded payload
	bobPlaintext, err := pigeonhole.ExtractMessageFromPaddedPayload(bobPaddedPlaintext)
	require.NoError(t, err, "Failed to extract message from padded payload")

	require.True(t, bytes.Equal(writeData, bobPlaintext),
		"Retrieved data must match written data - got: %s, expected: %s", string(bobPlaintext), string(writeData))

	t.Logf("SUCCESS: Proxy read succeeded! Retrieved data: %s", string(bobPlaintext))

	// Wait for cleanup
	time.Sleep(5 * time.Second)
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
