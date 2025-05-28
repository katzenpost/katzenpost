// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
)

func TestEnvelopeUnmarshaling(t *testing.T) {
	mkemNikeScheme := mkem.NewScheme(schemes.ByName("x25519"))

	replica1pub, _, err := mkemNikeScheme.GenerateKeyPair()
	require.NoError(t, err)
	replica2pub, _, err := mkemNikeScheme.GenerateKeyPair()
	require.NoError(t, err)

	request := make([]byte, 32)
	_, err = rand.Reader.Read(request)
	require.NoError(t, err)

	senderPrivateKey, ciphertext := mkemNikeScheme.Encapsulate([]nike.PublicKey{replica1pub, replica2pub}, request)
	senderPublicKey := senderPrivateKey.Public()

	envelope := CourierEnvelope{
		SenderEPubKey:        senderPublicKey.Bytes(),
		IntermediateReplicas: [2]uint8{1, 2},
		DEK:                  [2]*[mkem.DEKSize]byte{ciphertext.DEKCiphertexts[0], ciphertext.DEKCiphertexts[1]},
		Ciphertext:           ciphertext.Envelope,
		IsRead:               true,
	}

	cborBlob1 := envelope.Bytes()

	msg1, err := CourierEnvelopeFromBytes(cborBlob1)
	require.NoError(t, err)

	require.Equal(t, msg1.IsRead, envelope.IsRead)

	zeros := make([]byte, 64)
	cborBlob2 := append(cborBlob1, zeros...)
	_, err = CourierEnvelopeFromBytes(cborBlob2)
	require.NoError(t, err)
}
