// SPDX-FileCopyrightText: © 2026 David Stainton
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
	"github.com/katzenpost/katzenpost/pigeonhole"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// waitForReplicasReady gives every replica a synchronised PKI view, so
// that shard membership agrees across the fleet before a test relies on
// which replicas hold a box.
func waitForReplicasReady(t *testing.T, env *testEnvironment) {
	t.Helper()
	time.Sleep(5 * time.Second)
	for i, r := range env.replicas {
		t.Logf("FAILOVER_TEST: forcing PKI fetch for replica %d", i)
		require.NoError(t, r.PKIWorker.ForceFetchPKI())
	}
	time.Sleep(2 * time.Second)
}

// nonShardReplicas picks two replicas that do not hold the box, so a
// write addressed to them is forced down the proxy path.
func nonShardReplicas(t *testing.T, env *testEnvironment, sharding *shardingResult, replicaEpoch uint64) ([2]uint8, []nike.PublicKey) {
	t.Helper()
	currentEpoch, _, _ := epochtime.Now()
	doc := env.mockPKIClient.docs[currentEpoch]

	var indices [2]uint8
	pubKeys := make([]nike.PublicKey, 2)
	found := 0
	for i := 0; i < len(doc.StorageReplicas) && found < 2; i++ {
		isShard := false
		for _, shardIdx := range sharding.ReplicaIndices {
			if uint8(i) == shardIdx {
				isShard = true
				break
			}
		}
		if isShard {
			continue
		}
		pubKey, err := replicaCommon.NikeScheme.UnmarshalBinaryPublicKey(
			doc.StorageReplicas[i].EnvelopeKeys[replicaEpoch])
		require.NoError(t, err)
		indices[found] = uint8(i)
		pubKeys[found] = pubKey
		found++
	}
	require.Equal(t, 2, found, "need two non-shard replicas to force proxying")
	return indices, pubKeys
}

// sendEnvelope encapsulates inner to the given replicas, sends it
// through the courier and returns the decrypted reply.
func sendEnvelope(t *testing.T, env *testEnvironment, inner *pigeonhole.ReplicaInnerMessage, indices [2]uint8, pubKeys []nike.PublicKey, replicaEpoch uint64) *pigeonhole.ReplicaMessageReplyInnerMessage {
	t.Helper()

	padded, err := pigeonhole.PadInnerMessageForEncryption(inner, env.geometry)
	require.NoError(t, err)

	privKey, ciphertext, err := mkemNikeScheme.Encapsulate(pubKeys, padded)
	require.NoError(t, err)
	senderPubkeyBytes := privKey.Public().Bytes()

	envelope := &pigeonhole.CourierEnvelope{
		IntermediateReplicas: indices,
		Dek1:                 [mkem.DEKSize]byte(ciphertext.DEKCiphertexts[0]),
		Dek2:                 [mkem.DEKSize]byte(ciphertext.DEKCiphertexts[1]),
		ReplyIndex:           0,
		Epoch:                replicaEpoch,
		SenderPubkeyLen:      uint16(len(senderPubkeyBytes)),
		SenderPubkey:         senderPubkeyBytes,
		CiphertextLen:        uint32(len(ciphertext.Envelope)),
		Ciphertext:           ciphertext.Envelope,
	}

	reply := injectCourierEnvelope(t, env, envelope)
	require.NotNil(t, reply, "courier must return a reply")
	if len(reply.Payload) == 0 {
		reply = waitForReplicaResponse(t, env, envelope)
		require.NotNil(t, reply, "must receive the replica's response after waiting")
	}
	require.Greater(t, len(reply.Payload), 0, "the replica must return an envelope")

	replicaPubKey := env.replicaKeys[indices[reply.ReplyIndex]][replicaEpoch]
	rawInner, err := mkemNikeScheme.DecryptEnvelope(privKey, replicaPubKey, reply.Payload)
	require.NoError(t, err)
	innerBytes, err := pigeonhole.ExtractMessageFromPaddedPayload(rawInner)
	require.NoError(t, err)
	replyInner, err := pigeonhole.ParseReplicaMessageReplyInnerMessage(innerBytes)
	require.NoError(t, err)
	return replyInner
}

// bacapWrite encrypts payload into the writer's next BACAP box and
// returns the box ID and the write to send.
func bacapWrite(t *testing.T, env *testEnvironment, writer *writerSide, payload []byte) (*[bacap.BoxIDSize]byte, *pigeonhole.ReplicaInnerMessage) {
	t.Helper()

	padded, err := pigeonhole.CreatePaddedPayload(payload, env.geometry.MaxPlaintextPayloadLength+4)
	require.NoError(t, err)
	boxID, ciphertext, sigraw, err := writer.next.EncryptForContext(writer.writeCap, constants.PIGEONHOLE_CTX, padded)
	require.NoError(t, err)
	writer.next, err = writer.next.NextIndex()
	require.NoError(t, err)

	sig := [bacap.SignatureSize]byte{}
	copy(sig[:], sigraw)
	return &boxID, &pigeonhole.ReplicaInnerMessage{
		MessageType: 1, // 1 = write
		WriteMsg: &pigeonhole.ReplicaWrite{
			BoxID:      boxID,
			Signature:  sig,
			PayloadLen: uint32(len(ciphertext)),
			Payload:    ciphertext,
		},
	}
}

// TestProxyFailsOverWhenHolderIsDown takes one shard holder out and
// writes the box through replicas that hold neither copy. The write
// must degrade to the surviving holder rather than into a client-visible
// error, and it must do so well inside ProxyRequestTimeout: a request
// that cannot be handed to a peer at all is failed immediately rather
// than waiting out its share of the sweep budget.
//
// The sweep is pinned at the downed holder so that it is genuinely
// tried. Left to its usual random choice the live holder leads half the
// time, answers at once, and the test passes having exercised no
// failover and timed nothing but a healthy write.
func TestProxyFailsOverWhenHolderIsDown(t *testing.T) {
	env := setupTestEnvironment6Replicas(t)
	defer env.cleanup()
	waitForReplicasReady(t, env)

	owner, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	writer := &writerSide{owner, owner.GetMessageBoxIndex()}
	reader := &readerSide{owner.ReadCap(), owner.GetMessageBoxIndex()}

	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	payload := []byte("failover must degrade to the surviving holder")
	boxID, writeMsg := bacapWrite(t, env, writer, payload)
	sharding := getShardingInfo(t, env, boxID)

	// Take one holder out. The other stays up.
	downed := sharding.ReplicaIndices[0]
	t.Logf("FAILOVER_TEST: shutting down holder replica %d, leaving replica %d",
		downed, sharding.ReplicaIndices[1])
	env.replicas[downed].Shutdown()
	env.replicas[downed].Wait()

	// Aim every surviving replica's sweep at the downed holder. Index 0
	// is into the shard list GetShards returns for this box, which is
	// the list getShardingInfo reported, so this is the holder shut down
	// above.
	pinSweepAtDownedHolder(t, env, downed)

	indices, pubKeys := nonShardReplicas(t, env, sharding, replicaEpoch)

	timeout := time.Duration(env.replicaConfigs[indices[0]].ProxyRequestTimeout) * time.Second
	start := time.Now()
	inner := sendEnvelope(t, env, writeMsg, indices, pubKeys, replicaEpoch)
	elapsed := time.Since(start)

	require.NotNil(t, inner.WriteReply)
	require.Equal(t, pigeonhole.ReplicaSuccess, inner.WriteReply.ErrorCode,
		"one downed holder must degrade to its live peer, not into an error")
	// The sweep budget is divided among the candidates, so a first
	// holder that was waited out rather than failed fast would alone
	// cost timeout/2. Assert well inside that: the observed cost here
	// is the courier's response polling, not the proxy.
	require.Less(t, elapsed, timeout/4,
		"an unreachable holder must fail fast, not consume its share of the sweep budget")
	t.Logf("FAILOVER_TEST: proxied write completed in %v against a %v budget", elapsed, timeout)

	// Read straight from both shard holders: the courier still reaches
	// the live one although the other is down.
	readMsg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 0, // 0 = read
		ReadMsg:     &pigeonhole.ReplicaRead{BoxID: *boxID},
	}
	inner = sendEnvelope(t, env, readMsg, sharding.ReplicaIndices, sharding.ReplicaPubKeys, replicaEpoch)
	require.NotNil(t, inner.ReadReply)
	require.Equal(t, pigeonhole.ReplicaSuccess, inner.ReadReply.ErrorCode)

	paddedPlaintext := reader.open(t, *boxID, inner.ReadReply.Payload, inner.ReadReply.Signature[:])
	plaintext, err := pigeonhole.ExtractMessageFromPaddedPayload(paddedPlaintext)
	require.NoError(t, err)
	require.True(t, bytes.Equal(payload, plaintext), "the surviving holder must serve the real payload")
}

// pinSweepAtDownedHolder makes every replica still running try the first
// of a box's shard holders before any other, so a test that downed that
// holder measures failover on every run instead of on a coin flip.
func pinSweepAtDownedHolder(t *testing.T, env *testEnvironment, downed uint8) {
	t.Helper()
	for i, r := range env.replicas {
		if uint8(i) == downed {
			continue
		}
		t.Cleanup(r.PinFirstShardCandidate(0))
	}
}
