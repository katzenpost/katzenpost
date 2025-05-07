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

	_, ciphertextBlob := mkemNikeScheme.Encapsulate([]nike.PublicKey{replica1pub, replica2pub}, request)

	ciphertext, err := mkem.CiphertextFromBytes(mkemNikeScheme, ciphertextBlob)
	require.NoError(t, err)

	dek1 := &[32]byte{}
	dek2 := &[32]byte{}
	copy(dek1[:], ciphertext.DEKCiphertexts[0])
	copy(dek2[:], ciphertext.DEKCiphertexts[1])

	envelope := CourierEnvelope{
		SenderEPubKey:        [2][]byte{replica1pub.Bytes(), replica2pub.Bytes()},
		IntermediateReplicas: [2]uint8{1, 2},
		DEK:                  [2]*[32]byte{dek1, dek2},
		Ciphertext:           ciphertext.Envelope,
	}

	cborBlob1 := envelope.Bytes()

	_, err = CourierEnvelopeFromBytes(cborBlob1)
	require.NoError(t, err)

	zeros := make([]byte, 64)
	cborBlob2 := append(cborBlob1, zeros...)
	_, err = CourierEnvelopeFromBytes(cborBlob2)
	require.NoError(t, err)
}
