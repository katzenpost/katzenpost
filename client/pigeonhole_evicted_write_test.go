// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/pigeonhole"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// writeReplyAfterACK sends a replica write reply with replicaErr through a
// real SURB to a tracked write in the ACKReceived state, as a courier
// answers the follow-up poll, and returns the thin client answers.
func writeReplyAfterACK(t *testing.T, replicaErr uint8, noIdempotentBoxAlreadyExists bool) []*thin.StartResendingEncryptedMessageReply {
	t.Helper()
	cfg, err := config.LoadFile(testClientTOML)
	require.NoError(t, err)
	sphinxInstance, err := sphinx.FromGeometry(cfg.SphinxGeometry)
	require.NoError(t, err)

	loadCTIDHFixtures()
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	epoch, _, _ := epochtime.Now()
	doc := &cpki.Document{Epoch: epoch}
	for i := uint8(0); i < 2; i++ {
		doc.StorageReplicas = append(doc.StorageReplicas, &cpki.ReplicaDescriptor{
			ReplicaID:    i,
			EnvelopeKeys: map[uint64][]byte{replicaEpoch: ctidhFixtures[3+i].PubBytes},
		})
	}

	l := newSchedulerListener()
	d, _ := newARQTestDaemon(t, l)
	d.client = &Client{cfg: cfg, sphinx: sphinxInstance, pki: &pki{}}
	d.client.pki.c = d.client
	d.client.pki.docs.Store(epoch, &CachedDoc{Doc: doc})
	conn := newTestIncomingConn(0x5C, 1, 1)
	l.testRegister(conn)

	clientPriv, err := ctidhFixtures[5].Priv.MarshalBinary()
	require.NoError(t, err)
	desc, err := (&EnvelopeDescriptor{EnvelopeKey: clientPriv, ReplicaNums: [2]uint8{0, 1}, Epoch: replicaEpoch}).Bytes()
	require.NoError(t, err)

	nodes, path := createNikePathVector(require.New(t), cfg.SphinxGeometry.NIKEName, 5)
	surb, surbKeys, err := sphinxInstance.NewSURB(rand.Reader, path)
	require.NoError(t, err)

	m := trackARQMessage(d, conn.appID)
	m.SURBDecryptionKeys = surbKeys
	m.EnvelopeDescriptor = desc
	m.State = ARQStateACKReceived
	m.QueryID = &[thin.QueryIDLength]byte{0x67}
	m.NoIdempotentBoxAlreadyExists = noIdempotentBoxAlreadyExists

	inner := (&pigeonhole.ReplicaMessageReplyInnerMessage{
		MessageType: 1,
		WriteReply:  &pigeonhole.ReplicaWriteReply{ErrorCode: replicaErr},
	}).Bytes()
	padded, err := pigeonhole.CreatePaddedPayload(inner, len(inner)+4)
	require.NoError(t, err)
	encrypted, err := replicaCommon.MKEMNikeScheme.EnvelopeReply(ctidhFixtures[3].Priv, ctidhFixtures[5].Pub, padded)
	require.NoError(t, err)

	courierReply := &pigeonhole.CourierQueryReply{
		EnvelopeReply: &pigeonhole.CourierEnvelopeReply{
			EnvelopeHash: *m.EnvelopeHash,
			ReplyType:    pigeonhole.ReplyTypePayload,
			PayloadLen:   uint32(len(encrypted.Envelope)),
			Payload:      encrypted.Envelope,
		},
	}
	replyBytes, err := courierReply.MarshalBinary()
	require.NoError(t, err)
	payload := make([]byte, cfg.SphinxGeometry.ForwardPayloadLength)
	copy(payload, replyBytes)
	pkt, _, err := sphinxInstance.NewPacketFromSURB(surb, payload)
	require.NoError(t, err)
	var ciphertext []byte
	for i := range nodes {
		ciphertext, _, _, err = sphinxInstance.Unwrap(nodes[i].privateKey, pkt)
		require.NoError(t, err)
	}

	d.handlePigeonholeARQReply(m, &sphinxReply{surbID: m.SURBID, ciphertext: ciphertext})

	var answers []*thin.StartResendingEncryptedMessageReply
	conn.sendQueueMu.Lock()
	for _, r := range conn.sendQueue {
		if r.StartResendingEncryptedMessageReply != nil {
			answers = append(answers, r.StartResendingEncryptedMessageReply)
		}
	}
	conn.sendQueueMu.Unlock()
	return answers
}

// TestARQEvictedWriteReplyReturnBoxExists covers a write whose successful
// reply the courier evicted from its dedup cache after the initial ACK.
// The follow-up poll makes the courier dispatch the envelope again, and
// the replicas answer BoxAlreadyExists for the box this operation stored.
// StartResendingEncryptedMessageReturnBoxExists reports that as
// ErrBoxAlreadyExists; the default variant reports success.
func TestARQEvictedWriteReplyReturnBoxExists(t *testing.T) {
	answers := writeReplyAfterACK(t, pigeonhole.ReplicaSuccess, true)
	require.Len(t, answers, 1)
	require.Equal(t, thin.ThinClientSuccess, answers[0].ErrorCode, "a retained reply reports the original success")

	answers = writeReplyAfterACK(t, pigeonhole.ReplicaErrorBoxAlreadyExists, true)
	require.Len(t, answers, 1)
	require.Equal(t, pigeonhole.ReplicaErrorBoxAlreadyExists, answers[0].ErrorCode,
		"after eviction ReturnBoxExists reports BoxAlreadyExists for its own write")

	answers = writeReplyAfterACK(t, pigeonhole.ReplicaErrorBoxAlreadyExists, false)
	require.Len(t, answers, 1)
	require.Equal(t, thin.ThinClientSuccess, answers[0].ErrorCode, "the default write treats it as idempotent success")
}
