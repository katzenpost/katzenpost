//go:build docker_test

// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/replica/common"
)

var nikeScheme nike.Scheme = schemes.ByName("CTIDH1024-X25519")
var mkemNikeScheme *mkem.Scheme = mkem.NewScheme(nikeScheme)

func testDockerCourierService(t *testing.T) {

	t.Log("TESTING COURIER SERVICE1")

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	logging := &config.Logging{
		Disable: false,
		File:    "",
		Level:   "DEBUG",
	}
	thin := thin.NewThinClient(thin.FromConfig(cfg), logging)
	t.Log("thin client Dialing")
	err = thin.Dial()
	require.NoError(t, err)
	require.Nil(t, err)
	t.Log("thin client connected")

	t.Log("TESTING COURIER SERVICE2")

	t.Log("thin client getting PKI doc")
	doc := thin.PKIDocument()
	require.NotNil(t, doc)
	require.NotEqual(t, doc.LambdaP, 0.0)

	// extract storage replica info
	replicas := doc.StorageReplicas
	replica0 := replicas[0]
	replica1 := replicas[1]
	replicaEpoch, _, _ := common.ReplicaNow()
	replica0EnvKeyRaw, ok := replica0.EnvelopeKeys[replicaEpoch]
	require.True(t, ok)
	replica1EnvKeyRaw, ok := replica1.EnvelopeKeys[replicaEpoch]
	require.True(t, ok)

	replica0pub, err := nikeScheme.UnmarshalBinaryPublicKey(replica0EnvKeyRaw)
	require.NoError(t, err)
	replica1pub, err := nikeScheme.UnmarshalBinaryPublicKey(replica1EnvKeyRaw)
	require.NoError(t, err)

	t.Log("TESTING COURIER SERVICE3")

	descs, err := thin.GetServices("courier")
	require.NoError(t, err)

	require.NotNil(t, descs)
	require.True(t, len(descs) > 0)

	target := descs[0]

	t.Log("TESTING COURIER SERVICE4")

	ctx := []byte("test-session")
	owner, err := bacap.NewBoxOwnerCap(rand.Reader)
	require.NoError(t, err)

	uread := owner.UniversalReadCap()

	writer, err := bacap.NewStatefulWriter(owner, ctx)
	require.NoError(t, err)

	reader, err := bacap.NewStatefulReader(uread, ctx)
	require.NoError(t, err)

	plaintextMessage1 := []byte("Hello world")

	boxID, ciphertext, sigraw, err := writer.EncryptNext(plaintextMessage1)
	require.NoError(t, err)

	sig := &[64]byte{}
	copy(sig[:], sigraw)

	writeRequest := commands.ReplicaWrite{
		BoxID:         &boxID,
		Signature:     sig,
		PayloadLength: uint32(len(ciphertext)),
		Payload:       ciphertext,
	}

	request := writeRequest.ToBytes()

	t.Log("TESTING COURIER SERVICE5")

	_, ciphertextBlob := mkemNikeScheme.Encapsulate([]nike.PublicKey{replica0pub, replica1pub}, request)

	mkemCiphertext, err := mkem.CiphertextFromBytes(mkemNikeScheme, ciphertextBlob)
	require.NoError(t, err)

	dek1 := &[32]byte{}
	dek2 := &[32]byte{}
	copy(dek1[:], mkemCiphertext.DEKCiphertexts[0])
	copy(dek2[:], mkemCiphertext.DEKCiphertexts[1])

	senderEPubKey, senderEPrivKey, err := mkemNikeScheme.GenerateKeyPair()
	require.NoError(t, err)

	envelope1 := common.CourierEnvelope{
		SenderEPubKey:        senderEPubKey.Bytes(),
		IntermediateReplicas: [2]uint8{0, 1},
		DEK:                  [2]*[32]byte{dek1, dek2},
		Ciphertext:           mkemCiphertext.Envelope,
	}

	messageBlob1 := envelope1.Bytes()
	nodeIdKey := hash.Sum256(target.MixDescriptor.IdentityKey)

	t.Log("TESTING COURIER SERVICE6")

	reply1 := sendAndWait(t, thin, messageBlob1, &nodeIdKey, target.RecipientQueueID)
	require.NotNil(t, reply1)

	// XXX Do more checks on reply, here.

	t.Log("TESTING COURIER SERVICE7")

	replicaRead := &common.ReplicaRead{
		BoxID: &boxID,
	}

	replicaReadBlob := replicaRead.ToBytes()
	_, replicaReadCiphertextBlob := mkemNikeScheme.Encapsulate([]nike.PublicKey{replica0pub, replica1pub}, replicaReadBlob)
	replicaReadCiphertext, err := mkem.CiphertextFromBytes(mkemNikeScheme, replicaReadCiphertextBlob)
	require.NoError(t, err)

	readDek1 := &[32]byte{}
	readDek2 := &[32]byte{}
	copy(readDek1[:], replicaReadCiphertext.DEKCiphertexts[0])
	copy(readDek2[:], replicaReadCiphertext.DEKCiphertexts[1])

	envelope2 := common.CourierEnvelope{
		SenderEPubKey:        senderEPubKey.Bytes(),
		IntermediateReplicas: [2]uint8{0, 1},
		DEK:                  [2]*[32]byte{readDek1, readDek2},
		Ciphertext:           replicaReadCiphertext.Envelope,
	}

	messageBlob2 := envelope2.Bytes()

	// send a read request
	reply2 := sendAndWait(t, thin, messageBlob2, &nodeIdKey, target.RecipientQueueID)
	require.NotNil(t, reply2)

	courierReply, err := common.CourierEnvelopeReplyFromBytes(reply2)
	require.NoError(t, err)

	replicaMessageReply := courierReply.Payload
	require.Equal(t, 0, replicaMessageReply.ErrorCode)

	replyReplica, err := doc.GetReplicaNodeByReplicaID(replicaMessageReply.ReplicaID)
	require.NoError(t, err)
	replicaPubKeyBlob := replyReplica.EnvelopeKeys[replicaEpoch]
	replicaPubKey, err := nikeScheme.UnmarshalBinaryPublicKey(replicaPubKeyBlob)
	require.NoError(t, err)

	replyEnvelopeBlob, err := mkemNikeScheme.DecryptEnvelope(senderEPrivKey, replicaPubKey, replicaMessageReply.EnvelopeReply)
	require.NoError(t, err)

	replicaMessageReplyInnerMessage, err := common.ReplicaMessageReplyInnerMessageFromBytes(replyEnvelopeBlob)
	require.NoError(t, err)
	require.NotNil(t, replicaMessageReplyInnerMessage.ReplicaReadReply)
	require.Nil(t, replicaMessageReplyInnerMessage.ReplicaWriteReply)

	cyphertext := replicaMessageReplyInnerMessage.ReplicaReadReply.Payload
	signature := replicaMessageReplyInnerMessage.ReplicaReadReply.Signature

	plaintextMessage2, err := reader.DecryptNext(ctx, boxID, cyphertext, *signature)
	require.NoError(t, err)
	require.Equal(t, plaintextMessage1, plaintextMessage2)
}
