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

	t.Log("thin client getting PKI doc")
	doc := thin.PKIDocument()
	require.NotNil(t, doc)
	require.NotEqual(t, doc.LambdaP, 0.0)

	descs, err := thin.GetServices("courier")
	require.NoError(t, err)

	require.NotNil(t, descs)
	require.True(t, len(descs) > 0)

	target := descs[0]

	// XXX we should get these out of the PKI doc
	replica1pub, _, err := mkemNikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	replica2pub, _, err := mkemNikeScheme.GenerateKeyPair()
	require.NoError(t, err)

	request := make([]byte, 32)
	_, err = rand.Reader.Read(request)
	require.NoError(t, err)

	_, ciphertextBlob := mkemNikeScheme.Encapsulate([]nike.PublicKey{replica1pub, replica2pub}, request)

	ciphertext, err := mkem.CiphertextFromBytes(mkemNikeScheme, ciphertextBlob)
	require.NoError(t, err)

	dek1 := &[32]byte{}
	dek2 := &[32]byte{}
	copy(dek1[:], ciphertext.DEKCiphertexts[0])
	copy(dek2[:], ciphertext.DEKCiphertexts[1])

	envelope := common.CourierEnvelope{
		SenderEPubKey: [2][]byte{replica1pub.Bytes(), replica2pub.Bytes()},
		Replicas:      [2]uint8{1, 2},
		DEK:           [2]*[32]byte{dek1, dek2},
		Ciphertext:    ciphertext.Envelope,
	}

	messageBlob := envelope.Marshal()
	nodeIdKey := hash.Sum256(target.MixDescriptor.IdentityKey)
	reply := sendAndWait(t, thin, messageBlob, &nodeIdKey, target.RecipientQueueID)
	require.NotNil(t, reply)
}
