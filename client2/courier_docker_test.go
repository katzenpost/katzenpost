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
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/replica/common"
)

var mkemNikeScheme *mkem.Scheme = mkem.NewScheme(common.NikeScheme)

func testDockerCourierService(t *testing.T) {

	t.Log("TESTING COURIER SERVICE1")

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	logging := &config.Logging{
		Disable: false,
		File:    "",
		Level:   "DEBUG",
	}
	thinClient := thin.NewThinClient(thin.FromConfig(cfg), logging)
	t.Log("thinClient Dialing")
	err = thinClient.Dial()
	require.NoError(t, err)
	require.Nil(t, err)
	t.Log("thin client connected")

	t.Log("TESTING COURIER SERVICE2")

	t.Log("thin client getting PKI doc")
	doc := thinClient.PKIDocument()
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

	replica0pub, err := common.NikeScheme.UnmarshalBinaryPublicKey(replica0EnvKeyRaw)
	require.NoError(t, err)
	replica1pub, err := common.NikeScheme.UnmarshalBinaryPublicKey(replica1EnvKeyRaw)
	require.NoError(t, err)

	t.Log("TESTING COURIER SERVICE3")

	descs, err := thinClient.GetServices("courier")
	require.NoError(t, err)

	require.NotNil(t, descs)
	require.True(t, len(descs) > 0)

	courierDesc := descs[0]

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
		BoxID:     &boxID,
		Signature: sig,
		Payload:   ciphertext,
	}

	request := writeRequest.ToBytes()

	t.Log("TESTING COURIER SERVICE5")

	mkemPrivateKey, mkemCiphertext := mkemNikeScheme.Encapsulate([]nike.PublicKey{replica0pub, replica1pub}, request)
	mkemPublicKey := mkemPrivateKey.Public()

	dek0 := &[mkem.DEKSize]byte{}
	dek1 := &[mkem.DEKSize]byte{}
	copy(dek0[:], mkemCiphertext.DEKCiphertexts[0][:])
	copy(dek1[:], mkemCiphertext.DEKCiphertexts[1][:])

	envelope1 := common.CourierEnvelope{
		SenderEPubKey:        mkemPublicKey.Bytes(),
		IntermediateReplicas: [2]uint8{0, 1}, // indices to pkidoc's StorageReplicas
		DEK:                  [2]*[mkem.DEKSize]byte{dek0, dek1},
		Ciphertext:           mkemCiphertext.Envelope,
	}

	messageBlob1 := envelope1.Bytes()
	nodeIdKey := hash.Sum256(courierDesc.MixDescriptor.IdentityKey)

	t.Log("TESTING COURIER SERVICE6")

	reply1 := sendAndWait(t, thinClient, messageBlob1, &nodeIdKey, courierDesc.RecipientQueueID)
	require.NotNil(t, reply1)

	// XXX Do more checks on reply, here.

	// --- Now we're done sending. And now we read the box.

	t.Log("TESTING COURIER SERVICE7")

	replicaRead := &common.ReplicaRead{
		BoxID: &boxID,
	}

	replicaReadBlob := replicaRead.ToBytes()
	readerPrivateKey, replicaReadCiphertext := mkemNikeScheme.Encapsulate([]nike.PublicKey{replica0pub, replica1pub}, replicaReadBlob)

	readDek0 := &[mkem.DEKSize]byte{}
	readDek1 := &[mkem.DEKSize]byte{}
	copy(readDek0[:], replicaReadCiphertext.DEKCiphertexts[0][:])
	copy(readDek1[:], replicaReadCiphertext.DEKCiphertexts[1][:])

	envelope2 := common.CourierEnvelope{
		SenderEPubKey:        readerPrivateKey.Public().Bytes(),
		IntermediateReplicas: [2]uint8{0, 1},
		DEK:                  [2]*[mkem.DEKSize]byte{readDek0, readDek1},
		Ciphertext:           replicaReadCiphertext.Envelope,
	}

	for i := 0; i < 3; i++ {
		// send a read request
		courierReplyBlob := sendAndWait(t, thinClient, envelope2.Bytes(), &nodeIdKey, courierDesc.RecipientQueueID)
		require.NotNil(t, courierReplyBlob)

		courierReply, err := common.CourierEnvelopeReplyFromBytes(courierReplyBlob)
		require.NoError(t, err)

		replicaMessageReply := courierReply.Payload
		require.Equal(t, replicaMessageReply.ErrorCode, uint8(0))

		replyReplica := replicas[replicaMessageReply.ReplicaID]
		replicaPubKeyBlob := replyReplica.EnvelopeKeys[replicaEpoch]
		replicaPubKey, err := common.NikeScheme.UnmarshalBinaryPublicKey(replicaPubKeyBlob)
		require.NoError(t, err)

		t.Logf("EnvelopeReply length %d", len(replicaMessageReply.EnvelopeReply))

		if len(replicaMessageReply.EnvelopeReply) != 0 {
			replyEnvelopeBlob, err := mkemNikeScheme.DecryptEnvelope(readerPrivateKey, replicaPubKey, replicaMessageReply.EnvelopeReply)
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

			break
		}
	}

	t.Log("Test Completed. Disconnecting...")
	thinClient.Close()
}
