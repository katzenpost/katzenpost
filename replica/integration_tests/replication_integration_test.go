// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
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

// TestReplicaReplication tests that when a write is sent to an intermediary replica
// (which is NOT in the destination shard), the data gets replicated to both
// replicas in the destination shard.
//
// The test flow:
// 1. Write via courier to non-shard intermediary replicas
// 2. The intermediary writes locally AND replicates to the shard replicas
// 3. Read from each shard replica individually to verify both received the data
func TestReplicaReplication(t *testing.T) {
	// Need 6 replicas to ensure we have non-shard intermediaries available
	env := setupTestEnvironment6Replicas(t)
	var cleanupDone bool
	defer func() {
		if !cleanupDone {
			env.cleanup()
		}
	}()

	// Wait for replicas to be ready and PKI documents to be synchronized
	t.Logf("REPLICATION_TEST: Waiting for replicas to fully initialize...")
	time.Sleep(5 * time.Second)

	// Force all replicas to fetch PKI documents to ensure consistency
	for i, replica := range env.replicas {
		t.Logf("REPLICATION_TEST: Forcing PKI fetch for replica %d", i)
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

	// --- STEP 1: Determine the BoxID and find shard vs non-shard replicas ---
	writeData := []byte("test data for replication verification")

	// Create padded payload with length prefix for BACAP
	paddedPayload, err := pigeonhole.CreatePaddedPayload(writeData, env.geometry.MaxPlaintextPayloadLength+4)
	require.NoError(t, err)

	// Encrypt with BACAP - this produces the BoxID
	boxID, ciphertext, sigraw, err := aliceStatefulWriter.EncryptNext(paddedPayload)
	require.NoError(t, err)

	t.Logf("REPLICATION_TEST: BoxID: %x", boxID[:8])

	// Get the shard replicas for this BoxID
	sharding := getShardingInfo(t, env, &boxID)
	t.Logf("REPLICATION_TEST: Shard replicas for BoxID: %d, %d",
		sharding.ReplicaIndices[0], sharding.ReplicaIndices[1])

	// Find two replicas that are NOT in the shard (to use as intermediaries)
	var intermediaryIndices [2]uint8
	var intermediaryPubKeys []nike.PublicKey = make([]nike.PublicKey, 2)
	nonShardCount := 0

	currentEpoch, _, _ := epochtime.Now()
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
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
			intermediaryIndices[nonShardCount] = uint8(i)
			pubKey, err := replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(
				doc.StorageReplicas[i].EnvelopeKeys[replicaEpoch])
			require.NoError(t, err)
			intermediaryPubKeys[nonShardCount] = pubKey
			nonShardCount++
		}
	}
	require.Equal(t, 2, nonShardCount, "Should find at least 2 non-shard replicas for intermediaries")

	t.Logf("REPLICATION_TEST: Using non-shard intermediary replicas: %d, %d",
		intermediaryIndices[0], intermediaryIndices[1])

	// --- STEP 2: Write via non-shard intermediaries ---
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

	// Create MKEM envelope for the write operation to NON-SHARD intermediaries
	mkemPrivateKey, mkemCiphertext := mkemNikeScheme.Encapsulate(intermediaryPubKeys, writeMsg.Bytes())
	mkemPublicKey := mkemPrivateKey.Public()
	senderPubkeyBytes := mkemPublicKey.Bytes()

	writeEnvelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: intermediaryIndices, // Non-shard intermediaries!
		Dek1:                 *mkemCiphertext.DEKCiphertexts[0],
		Dek2:                 *mkemCiphertext.DEKCiphertexts[1],
		ReplyIndex:           0,
		Epoch:                replicaEpoch,
		SenderPubkeyLen:      uint16(len(senderPubkeyBytes)),
		SenderPubkey:         senderPubkeyBytes,
		CiphertextLen:        uint32(len(mkemCiphertext.Envelope)),
		Ciphertext:           mkemCiphertext.Envelope,
	}

	t.Logf("REPLICATION_TEST: Writing via non-shard intermediaries, expecting replication to shards")
	writeReply := injectCourierEnvelope(t, env, writeEnvelope)
	require.NotNil(t, writeReply)
	t.Logf("REPLICATION_TEST: Write completed via intermediaries")

	// Wait for replication to complete
	t.Logf("REPLICATION_TEST: Waiting for replication to propagate to shard replicas...")
	time.Sleep(10 * time.Second)

	// --- STEP 3: Read from EACH shard replica individually to verify replication ---
	// Get the BoxID Bob expects to read (same as what Alice wrote)
	expectedBoxID, err := bobStatefulReader.NextBoxID()
	require.NoError(t, err)
	require.Equal(t, boxID, *expectedBoxID, "Bob's expected BoxID should match Alice's written BoxID")

	// Verify both shard replicas have the data
	for shardNum, shardIdx := range sharding.ReplicaIndices {
		t.Logf("REPLICATION_TEST: Reading from shard replica %d (index %d)", shardNum, shardIdx)

		// Create a read request targeting this specific shard replica
		// We'll send to both shard replicas but we're interested in verifying each one
		readReply := readFromSpecificReplica(t, env, expectedBoxID, shardIdx, replicaEpoch)

		require.NotNil(t, readReply, "Shard replica %d should return a reply", shardIdx)
		require.NotNil(t, readReply.ReadReply, "Shard replica %d should return a ReadReply", shardIdx)
		require.Equal(t, pigeonhole.ReplicaSuccess, readReply.ReadReply.ErrorCode,
			"Shard replica %d should have the data (error code: %d)", shardIdx, readReply.ReadReply.ErrorCode)

		// Decrypt and verify the data
		var signature [64]byte
		copy(signature[:], readReply.ReadReply.Signature[:])

		// Create a fresh reader for each verification (since DecryptNext advances state)
		verifyReader, err := bacap.NewStatefulReader(bobReadCap, constants.PIGEONHOLE_CTX)
		require.NoError(t, err)
		verifyBoxID, err := verifyReader.NextBoxID()
		require.NoError(t, err)

		decryptedPadded, err := verifyReader.DecryptNext(
			constants.PIGEONHOLE_CTX, *verifyBoxID, readReply.ReadReply.Payload, signature)
		require.NoError(t, err, "Failed to decrypt data from shard replica %d", shardIdx)

		decryptedData, err := pigeonhole.ExtractMessageFromPaddedPayload(decryptedPadded)
		require.NoError(t, err, "Failed to extract message from shard replica %d", shardIdx)

		require.True(t, bytes.Equal(writeData, decryptedData),
			"Data from shard replica %d should match original - got: %s, expected: %s",
			shardIdx, string(decryptedData), string(writeData))

		t.Logf("REPLICATION_TEST: SUCCESS - Shard replica %d has correct data: %s", shardIdx, string(decryptedData))
	}

	t.Logf("REPLICATION_TEST: SUCCESS - Both shard replicas have the replicated data!")

	cleanupDone = true
	env.cleanup()
}

// readFromSpecificReplica sends a read request to a specific replica and returns the inner message reply
func readFromSpecificReplica(t *testing.T, env *testEnvironment, boxID *[bacap.BoxIDSize]byte, replicaIdx uint8, replicaEpoch uint64) *pigeonhole.ReplicaMessageReplyInnerMessage {
	currentEpoch, _, _ := epochtime.Now()
	doc := env.mockPKIClient.docs[currentEpoch]

	// Get the public key for the target replica
	targetPubKeyBytes := doc.StorageReplicas[replicaIdx].EnvelopeKeys[replicaEpoch]
	targetPubKey, err := replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(targetPubKeyBytes)
	require.NoError(t, err)

	// For MKEM we need 2 keys, so we'll use the same replica twice
	// This effectively makes a single-recipient envelope
	replicaPubKeys := []nike.PublicKey{targetPubKey, targetPubKey}
	indices := [2]uint8{replicaIdx, replicaIdx}

	readRequest := &pigeonhole.ReplicaRead{
		BoxID: *boxID,
	}
	readMsg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 0, // 0 = read
		ReadMsg:     readRequest,
	}

	mkemPrivateKey, mkemCiphertext := mkemNikeScheme.Encapsulate(replicaPubKeys, readMsg.Bytes())
	mkemPublicKey := mkemPrivateKey.Public()
	senderPubkeyBytes := mkemPublicKey.Bytes()

	readEnvelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: indices,
		Dek1:                 *mkemCiphertext.DEKCiphertexts[0],
		Dek2:                 *mkemCiphertext.DEKCiphertexts[1],
		ReplyIndex:           0,
		Epoch:                replicaEpoch,
		SenderPubkeyLen:      uint16(len(senderPubkeyBytes)),
		SenderPubkey:         senderPubkeyBytes,
		CiphertextLen:        uint32(len(mkemCiphertext.Envelope)),
		Ciphertext:           mkemCiphertext.Envelope,
	}

	t.Logf("REPLICATION_TEST: Sending read request to replica %d for BoxID %x", replicaIdx, boxID[:8])
	readReply := injectCourierEnvelope(t, env, readEnvelope)
	require.NotNil(t, readReply, "Should receive reply from replica %d", replicaIdx)

	// If we didn't get a payload immediately, wait for it
	if len(readReply.Payload) == 0 {
		t.Logf("REPLICATION_TEST: No immediate payload from replica %d, waiting...", replicaIdx)
		readReply = waitForReplicaResponse(t, env, readEnvelope)
		require.NotNil(t, readReply, "Should receive response from replica %d after waiting", replicaIdx)
	}

	require.Greater(t, len(readReply.Payload), 0, "Replica %d should return a payload", replicaIdx)

	// Decrypt the MKEM envelope
	replicaPubKey := env.replicaKeys[replicaIdx][replicaEpoch]
	rawInnerMsg, err := mkemNikeScheme.DecryptEnvelope(mkemPrivateKey, replicaPubKey, readReply.Payload)
	require.NoError(t, err, "Failed to decrypt reply from replica %d", replicaIdx)

	innerMsg, err := pigeonhole.ParseReplicaMessageReplyInnerMessage(rawInnerMsg)
	require.NoError(t, err, "Failed to parse reply from replica %d", replicaIdx)

	return innerMsg
}
