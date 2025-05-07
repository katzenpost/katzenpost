//go:build docker_test

// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/courier/common"
)

var mkemNikeScheme *mkem.Scheme = mkem.NewScheme(schemes.ByName("x25519"))

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
	replica0EnvKey, ok := replica0.EnvelopeKeys[replicaEpoch]
	require.True(t, ok)
	replica1EnvKey, ok := replica1.EnvelopeKeys[replicaEpoch]
	require.True(t, ok)
	//replica0pub

	t.Log("TESTING COURIER SERVICE3")

	descs, err := thin.GetServices("courier")
	require.NoError(t, err)

	require.NotNil(t, descs)
	require.True(t, len(descs) > 0)

	target := descs[0]

	t.Log("TESTING COURIER SERVICE4")

	// XXX FIX ME
	request := make([]byte, 32)
	_, err = rand.Reader.Read(request)
	require.NoError(t, err)

	t.Log("TESTING COURIER SERVICE5")

	_, ciphertextBlob := mkemNikeScheme.Encapsulate([]nike.PublicKey{replica0pub, replica1pub}, request)

	ciphertext, err := mkem.CiphertextFromBytes(mkemNikeScheme, ciphertextBlob)
	require.NoError(t, err)

	dek1 := &[32]byte{}
	dek2 := &[32]byte{}
	copy(dek1[:], ciphertext.DEKCiphertexts[0])
	copy(dek2[:], ciphertext.DEKCiphertexts[1])

	envelope := common.CourierEnvelope{
		SenderEPubKey:        [2][]byte{replica1pub.Bytes(), replica2pub.Bytes()},
		IntermediateReplicas: [2]uint8{0, 1},
		DEK:                  [2]*[32]byte{dek1, dek2},
		Ciphertext:           ciphertext.Envelope,
	}

	messageBlob := envelope.Bytes()
	nodeIdKey := hash.Sum256(target.MixDescriptor.IdentityKey)

	t.Log("TESTING COURIER SERVICE6")

	reply := sendAndWait(t, thin, messageBlob, &nodeIdKey, target.RecipientQueueID)
	require.NotNil(t, reply)

	t.Log("TESTING COURIER SERVICE7")
}
