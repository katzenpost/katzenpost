// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/constants"
	"github.com/katzenpost/katzenpost/core/epochtime"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"

	"github.com/katzenpost/katzenpost/pigeonhole"
)

func TestProxyIntegration(t *testing.T) {
	// This test verifies proxy functionality works end-to-end using BACAP encryption.
	// It writes data via non-shard replicas (forcing proxy behavior), then reads
	// directly from the shard replicas and verifies the data is correctly retrieved.

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
	alice := &writerSide{aliceOwner, aliceOwner.GetMessageBoxIndex()}
	bobReadCap := aliceOwner.ReadCap()
	bob := &readerSide{bobReadCap, bobReadCap.GetMessageBoxIndex()}

	// --- STEP 1: Alice writes data using BACAP encryption via NON-shard replicas ---
	writeData := []byte("test data for proxy integration")

	// Create padded payload with length prefix for BACAP
	paddedPayload, err := pigeonhole.CreatePaddedPayload(writeData, env.geometry.MaxPlaintextPayloadLength+4)
	require.NoError(t, err)

	// Encrypt with BACAP - this produces the correct ciphertext size
	boxID, ciphertext, sigraw, err := alice.next.EncryptForContext(alice.writeCap, constants.PIGEONHOLE_CTX, paddedPayload)
	require.NoError(t, err)
	alice.next, err = alice.next.NextIndex()
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

	// Find two replicas that are NOT the correct shards
	var proxyIndices [2]uint8
	var proxyPubKeys []nike.PublicKey = make([]nike.PublicKey, 2)
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
			proxyIndices[nonShardCount] = uint8(i)
			pubKey, err := replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(
				doc.StorageReplicas[i].EnvelopeKeys[replicaEpoch])
			require.NoError(t, err)
			proxyPubKeys[nonShardCount] = pubKey
			nonShardCount++
		}
	}
	require.Equal(t, 2, nonShardCount, "Should find at least 2 non-shard replicas")

	t.Logf("PROXY_TEST: Alice will write via non-shard replicas: %d, %d (will proxy to correct shards: %d, %d)",
		proxyIndices[0], proxyIndices[1],
		sharding.ReplicaIndices[0], sharding.ReplicaIndices[1])

	// Create MKEM envelope for the write operation, targeting NON-shard replicas.
	// Length-prefix and pad to write size, matching PadInnerMessageForEncryption.
	paddedWriteMsg, err := pigeonhole.PadInnerMessageForEncryption(writeMsg, env.geometry)
	require.NoError(t, err)
	mkemPrivateKey, mkemCiphertext, err := mkemNikeScheme.Encapsulate(proxyPubKeys, paddedWriteMsg)
	require.NoError(t, err)
	mkemPublicKey := mkemPrivateKey.Public()
	senderPubkeyBytes := mkemPublicKey.Bytes()

	writeEnvelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: proxyIndices, // Non-shard replicas - will proxy!
		Dek1:                 [mkem.DEKSize]byte(mkemCiphertext.DEKCiphertexts[0]),
		Dek2:                 [mkem.DEKSize]byte(mkemCiphertext.DEKCiphertexts[1]),
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
	t.Logf("PROXY_TEST: Write completed via proxy")

	// Wait for write to propagate to the shards. injectCourierEnvelope
	// returns on the courier's immediate ACK, BEFORE the shards have
	// durably stored the write, and the proxied write adds another hop.
	// The subsequent read must not race replication. CI observed a 5s wait racing
	// the replication — harden the margin.
	time.Sleep(15 * time.Second)

	// --- STEP 2: Bob reads directly from the shard replicas ---
	// Get the BoxID Bob expects to read (same as what Alice wrote)
	expectedBoxID := bob.boxID(t)
	t.Logf("PROXY_TEST: Bob reads from BoxID: %x", expectedBoxID[:8])

	readRequest := &pigeonhole.ReplicaRead{
		BoxID: *expectedBoxID,
	}
	readMsg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 0, // 0 = read
		ReadMsg:     readRequest,
	}

	// Create MKEM envelope for read, targeting the shard replicas.
	// Pad the inner message to the write size (read is padded up for indistinguishability).
	paddedReadMsg, err := pigeonhole.PadInnerMessageForEncryption(readMsg, env.geometry)
	require.NoError(t, err)
	bobMkemPrivateKey, bobMkemCiphertext, err := mkemNikeScheme.Encapsulate(sharding.ReplicaPubKeys, paddedReadMsg)
	require.NoError(t, err)
	bobMkemPublicKey := bobMkemPrivateKey.Public()
	bobSenderPubkeyBytes := bobMkemPublicKey.Bytes()

	readEnvelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: sharding.ReplicaIndices,
		Dek1:                 [mkem.DEKSize]byte(bobMkemCiphertext.DEKCiphertexts[0]),
		Dek2:                 [mkem.DEKSize]byte(bobMkemCiphertext.DEKCiphertexts[1]),
		ReplyIndex:           0,
		Epoch:                replicaEpoch,
		SenderPubkeyLen:      uint16(len(bobSenderPubkeyBytes)),
		SenderPubkey:         bobSenderPubkeyBytes,
		CiphertextLen:        uint32(len(bobMkemCiphertext.Envelope)),
		Ciphertext:           bobMkemCiphertext.Envelope,
	}

	t.Logf("PROXY_TEST: Read envelope created, injecting to courier")
	readReply := injectCourierEnvelope(t, env, readEnvelope)
	require.NotNil(t, readReply, "Courier should return a reply")

	// If we didn't get a payload immediately, wait for the read to complete
	if len(readReply.Payload) == 0 {
		t.Logf("PROXY_TEST: No immediate payload, waiting for the read to complete...")
		readReply = waitForReplicaResponse(t, env, readEnvelope)
		require.NotNil(t, readReply, "Should receive read response after waiting")
	}

	require.Greater(t, len(readReply.Payload), 0, "Read must return a payload")
	t.Logf("PROXY_TEST: Received read reply with payload length: %d", len(readReply.Payload))

	// Decrypt the MKEM envelope to get the inner message
	replicaIndex := int(sharding.ReplicaIndices[readReply.ReplyIndex])
	replicaPubKey := env.replicaKeys[replicaIndex][replicaEpoch]
	rawInnerMsg, err := mkemNikeScheme.DecryptEnvelope(bobMkemPrivateKey, replicaPubKey, readReply.Payload)
	require.NoError(t, err, "Failed to decrypt read reply")

	innerBytes, err := pigeonhole.ExtractMessageFromPaddedPayload(rawInnerMsg)
	require.NoError(t, err, "Failed to extract padded reply inner message")
	innerMsg, err := pigeonhole.ParseReplicaMessageReplyInnerMessage(innerBytes)
	require.NoError(t, err, "Failed to parse replica message reply")
	require.NotNil(t, innerMsg.ReadReply, "ReadReply should not be nil")
	require.Equal(t, pigeonhole.ReplicaSuccess, innerMsg.ReadReply.ErrorCode,
		"Read of proxied write must succeed - error code: %d", innerMsg.ReadReply.ErrorCode)

	// Decrypt the BACAP payload at Bob's index
	readPos, err := bob.readCap.PositionAt(bob.next)
	require.NoError(t, err)
	bobPaddedPlaintext, err := pigeonhole.Open(readPos,
		*expectedBoxID, innerMsg.ReadReply.Payload, innerMsg.ReadReply.Signature[:])
	require.NoError(t, err, "Failed to decrypt BACAP payload")

	// Extract the actual message data from the padded payload
	bobPlaintext, err := pigeonhole.ExtractMessageFromPaddedPayload(bobPaddedPlaintext)
	require.NoError(t, err, "Failed to extract message from padded payload")

	require.True(t, bytes.Equal(writeData, bobPlaintext),
		"Retrieved data must match written data - got: %s, expected: %s", string(bobPlaintext), string(writeData))

	t.Logf("SUCCESS: Proxied write read back! Retrieved data: %s", string(bobPlaintext))

	// Wait for cleanup
	time.Sleep(5 * time.Second)
	cleanupDone = true
	env.cleanup()
}

// setupTestEnvironment6Replicas creates a test environment with 6 replicas for proxy testing
func setupTestEnvironment6Replicas(t *testing.T) *testEnvironment {
	// We need enough replicas for the proxy integration test that a box's
	// two shard replicas leave two non-shard replicas to proxy through.
	return setupTestEnvironmentWithReplicas(t, 6, "courier_replica_proxy_test_*")
}
