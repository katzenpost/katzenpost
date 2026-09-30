// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"

	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

func TestTryDecryptMKEMWithReplicas(t *testing.T) {
	loadCTIDHFixtures()
	mkemScheme := replicaCommon.MRHybridScheme

	// Use cached keypair fixtures instead of slow key generation
	replica0Pub := ctidhFixtures[0].Pub
	replica1Pub := ctidhFixtures[1].Pub

	// Client encapsulates to both replicas, obtaining one derived key per
	// recipient (mrhybrid has no shared ephemeral keypair to persist).
	plaintext := []byte("secret pigeonhole message")
	derivedKeys, _, err := mkemScheme.Encapsulate([]kem.PublicKey{replica0Pub, replica1Pub}, plaintext)
	require.NoError(t, err)

	// Replica 0 creates an envelope reply using its own derived key
	// (simulating what the replica does after Decapsulate).
	replyPayload := []byte("replica reply data")
	envelope0, err := mkemScheme.EnvelopeReply(derivedKeys[0], replyPayload)
	require.NoError(t, err)

	// Replica 1 creates a different envelope reply
	envelope1, err := mkemScheme.EnvelopeReply(derivedKeys[1], replyPayload)
	require.NoError(t, err)

	envelopeDescKeys := [2][]byte{derivedKeys[0], derivedKeys[1]}

	t.Run("decrypts with first replica key", func(t *testing.T) {
		decrypted, replicaNum, err := tryDecryptMKEMWithReplicas(
			mkemScheme, envelopeDescKeys, envelope0, [2]uint8{0, 1},
		)
		require.NoError(t, err)
		require.Equal(t, replyPayload, decrypted)
		require.Equal(t, uint8(0), replicaNum)
	})

	t.Run("tries second replica when first fails", func(t *testing.T) {
		decrypted, replicaNum, err := tryDecryptMKEMWithReplicas(
			mkemScheme, envelopeDescKeys, envelope1, [2]uint8{0, 1},
		)
		require.NoError(t, err)
		require.Equal(t, replyPayload, decrypted)
		require.Equal(t, uint8(1), replicaNum)
	})

	t.Run("fails when no replica key works", func(t *testing.T) {
		wrongKeys := [2][]byte{ctidhFixtures[2].PubBytes[:32], ctidhFixtures[2].PubBytes[:32]} // unrelated bytes, won't match either envelope

		_, _, err := tryDecryptMKEMWithReplicas(
			mkemScheme, wrongKeys, envelope0, [2]uint8{0, 1},
		)
		require.Error(t, err)
		require.ErrorIs(t, err, errMKEMDecryptionFailed)
	})

	t.Run("fails when no derived keys are available", func(t *testing.T) {
		_, _, err := tryDecryptMKEMWithReplicas(
			mkemScheme, [2][]byte{nil, nil}, envelope0, [2]uint8{0, 1},
		)
		require.Error(t, err)
		require.ErrorIs(t, err, errMKEMDecryptionFailed)
	})

	t.Run("skips a missing derived key and tries the next", func(t *testing.T) {
		decrypted, replicaNum, err := tryDecryptMKEMWithReplicas(
			mkemScheme, [2][]byte{nil, derivedKeys[1]}, envelope1, [2]uint8{0, 1},
		)
		require.NoError(t, err)
		require.Equal(t, replyPayload, decrypted)
		require.Equal(t, uint8(1), replicaNum)
	})
}
