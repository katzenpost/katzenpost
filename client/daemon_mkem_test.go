// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/protocols/mkem"

	"github.com/katzenpost/katzenpost/pigeonhole"
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
	envelopePrivKey, _, err := mkemScheme.Encapsulate([]nike.PublicKey{replica0Pub, replica1Pub}, plaintext)
	require.NoError(t, err)

	// Replica 0 creates an envelope reply (simulating what the replica does)
	replyPayload := []byte("replica reply data")
	reply0, err := mkemScheme.EnvelopeReply(replica0Priv, envelopePrivKey.Public(), replyPayload)
	require.NoError(t, err)
	envelope0 := reply0.Envelope

	// Replica 1 creates a different envelope reply
	reply1, err := mkemScheme.EnvelopeReply(replica1Priv, envelopePrivKey.Public(), replyPayload)
	require.NoError(t, err)
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

type dhCountingScheme struct {
	nike.Scheme
	n int
}

func (s *dhCountingScheme) DeriveSecret(p nike.PrivateKey, pub nike.PublicKey) []byte {
	s.n++
	return s.Scheme.DeriveSecret(p, pub)
}

func TestReplyOrderUsesReplyIndex(t *testing.T) {
	loadCTIDHFixtures()
	counting := &dhCountingScheme{Scheme: replicaCommon.NikeScheme}
	mkemScheme := mkem.NewScheme(counting)
	envelopePub, envelopePriv := ctidhFixtures[2].Pub, ctidhFixtures[2].Priv
	replicaPubKeys := map[uint8]nike.PublicKey{5: ctidhFixtures[0].Pub, 7: ctidhFixtures[1].Pub}
	nums := [2]uint8{5, 7}
	payload := []byte("reply")

	reply7, err := mkemScheme.EnvelopeReply(ctidhFixtures[1].Priv, envelopePub, payload)
	require.NoError(t, err)
	counting.n = 0
	got, replicaNum, err := tryDecryptMKEMWithReplicas(mkemScheme, envelopePriv, reply7.Envelope, replyOrder(nums, 1), replicaPubKeys)
	require.NoError(t, err)
	require.Equal(t, payload, got)
	require.Equal(t, uint8(7), replicaNum)
	require.Equal(t, 1, counting.n, "a reply from ReplicaNums[1] with ReplyIndex 1 needs one DH")

	// A wrong hint still decrypts, through the fallback.
	reply5, err := mkemScheme.EnvelopeReply(ctidhFixtures[0].Priv, envelopePub, payload)
	require.NoError(t, err)
	got, replicaNum, err = tryDecryptMKEMWithReplicas(mkemScheme, envelopePriv, reply5.Envelope, replyOrder(nums, 1), replicaPubKeys)
	require.NoError(t, err)
	require.Equal(t, payload, got)
	require.Equal(t, uint8(5), replicaNum)
}

func TestParseReplicaEnvelopeKeyFollowsKeyBytes(t *testing.T) {
	loadCTIDHFixtures()
	for _, f := range ctidhFixtures[:2] {
		pk, err := pigeonhole.ParseReplicaEnvelopeKey(f.PubBytes)
		require.NoError(t, err)
		require.Equal(t, f.PubBytes, pk.Bytes(), "a changed PKI key must not be served from the cache")
	}
	_, err := pigeonhole.ParseReplicaEnvelopeKey([]byte("short"))
	require.Error(t, err)
}
