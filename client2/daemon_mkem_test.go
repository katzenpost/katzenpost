// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike"

	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

func TestTryDecryptMKEMWithReplicas(t *testing.T) {
	loadCTIDHFixtures()
	mkemScheme := replicaCommon.MKEMNikeScheme

	// Use pre-generated CTIDH keypair fixtures instead of slow key generation
	replica0Pub := ctidhFixtures[0].Pub
	replica0Priv := ctidhFixtures[0].Priv
	replica1Pub := ctidhFixtures[1].Pub
	replica1Priv := ctidhFixtures[1].Priv

	// Client encapsulates to both replicas
	plaintext := []byte("secret pigeonhole message")
	envelopePrivKey, _ := mkemScheme.Encapsulate([]nike.PublicKey{replica0Pub, replica1Pub}, plaintext)

	// Replica 0 creates an envelope reply (simulating what the replica does)
	replyPayload := []byte("replica reply data")
	reply0 := mkemScheme.EnvelopeReply(replica0Priv, envelopePrivKey.Public(), replyPayload)
	envelope0 := reply0.Envelope

	// Replica 1 creates a different envelope reply
	reply1 := mkemScheme.EnvelopeReply(replica1Priv, envelopePrivKey.Public(), replyPayload)
	envelope1 := reply1.Envelope

	// Build the replica public keys map
	replicaPubKeys := map[uint8]nike.PublicKey{
		0: replica0Pub,
		1: replica1Pub,
	}

	t.Run("decrypts with first replica key", func(t *testing.T) {
		decrypted, replicaNum, err := tryDecryptMKEMWithReplicas(
			mkemScheme, envelopePrivKey, envelope0, []uint8{0, 1}, replicaPubKeys,
		)
		require.NoError(t, err)
		require.Equal(t, replyPayload, decrypted)
		require.Equal(t, uint8(0), replicaNum)
	})

	t.Run("tries second replica when first fails", func(t *testing.T) {
		decrypted, replicaNum, err := tryDecryptMKEMWithReplicas(
			mkemScheme, envelopePrivKey, envelope1, []uint8{0, 1}, replicaPubKeys,
		)
		require.NoError(t, err)
		require.Equal(t, replyPayload, decrypted)
		require.Equal(t, uint8(1), replicaNum)
	})

	t.Run("fails when no replica key works", func(t *testing.T) {
		wrongPriv := ctidhFixtures[2].Priv // Pre-generated, won't match either replica

		_, _, err := tryDecryptMKEMWithReplicas(
			mkemScheme, wrongPriv, envelope0, []uint8{0, 1}, replicaPubKeys,
		)
		require.Error(t, err)
		require.ErrorIs(t, err, errMKEMDecryptionFailed)
	})

	t.Run("fails with empty replica list", func(t *testing.T) {
		_, _, err := tryDecryptMKEMWithReplicas(
			mkemScheme, envelopePrivKey, envelope0, []uint8{}, replicaPubKeys,
		)
		require.Error(t, err)
		require.ErrorIs(t, err, errMKEMDecryptionFailed)
	})

	t.Run("skips missing replica keys", func(t *testing.T) {
		decrypted, replicaNum, err := tryDecryptMKEMWithReplicas(
			mkemScheme, envelopePrivKey, envelope0, []uint8{99, 0}, replicaPubKeys,
		)
		require.NoError(t, err)
		require.Equal(t, replyPayload, decrypted)
		require.Equal(t, uint8(0), replicaNum)
	})
}
