// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/pigeonhole"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// shardReadHarness is a daemon tracking one read in the ACKReceived state,
// to which courier replies are delivered through real SURBs.
type shardReadHarness struct {
	t      *testing.T
	cfg    *config.Config
	sphinx *sphinx.Sphinx
	d      *Daemon
	conn   *incomingConn
	m      *ARQMessage
}

func newShardReadHarness(t *testing.T, readCap *bacap.ReadCap, index []byte, noRetryOnBoxIDNotFound bool) *shardReadHarness {
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
	conn := newTestIncomingConn(0x5D, 1, 1)
	l.testRegister(conn)

	clientPriv, err := ctidhFixtures[5].Priv.MarshalBinary()
	require.NoError(t, err)
	desc, err := (&EnvelopeDescriptor{EnvelopeKey: clientPriv, ReplicaNums: [2]uint8{0, 1}, Epoch: replicaEpoch}).Bytes()
	require.NoError(t, err)

	m := trackARQMessage(d, conn.appID)
	m.EnvelopeDescriptor = desc
	m.State = ARQStateACKReceived
	m.QueryID = &[thin.QueryIDLength]byte{0x68}
	m.IsRead = true
	m.ReadCap = readCap
	m.MessageBoxIndex = index
	m.NoRetryOnBoxIDNotFound = noRetryOnBoxIDNotFound
	return &shardReadHarness{t: t, cfg: cfg, sphinx: sphinxInstance, d: d, conn: conn, m: m}
}

// deliver sends a courier envelope reply to the tracked read.
func (h *shardReadHarness) deliver(reply *pigeonhole.CourierEnvelopeReply) {
	t := h.t
	t.Helper()
	nodes, path := createNikePathVector(require.New(t), h.cfg.SphinxGeometry.NIKEName, 5)
	surb, surbKeys, err := h.sphinx.NewSURB(rand.Reader, path)
	require.NoError(t, err)
	h.m.SURBDecryptionKeys = surbKeys

	reply.EnvelopeHash = *h.m.EnvelopeHash
	replyBytes, err := (&pigeonhole.CourierQueryReply{EnvelopeReply: reply}).MarshalBinary()
	require.NoError(t, err)
	payload := make([]byte, h.cfg.SphinxGeometry.ForwardPayloadLength)
	copy(payload, replyBytes)
	pkt, _, err := h.sphinx.NewPacketFromSURB(surb, payload)
	require.NoError(t, err)
	var ciphertext []byte
	for i := range nodes {
		ciphertext, _, _, err = h.sphinx.Unwrap(nodes[i].privateKey, pkt)
		require.NoError(t, err)
	}
	h.d.handlePigeonholeARQReply(h.m, &sphinxReply{surbID: h.m.SURBID, ciphertext: ciphertext})
}

// readReply returns a courier payload reply carrying a replica read reply
// that shard replica 0 encrypted for the client.
func (h *shardReadHarness) readReply(inner *pigeonhole.ReplicaReadReply) *pigeonhole.CourierEnvelopeReply {
	t := h.t
	t.Helper()
	msg := (&pigeonhole.ReplicaMessageReplyInnerMessage{MessageType: 0, ReadReply: inner}).Bytes()
	padded, err := pigeonhole.CreatePaddedPayload(msg, len(msg)+4)
	require.NoError(t, err)
	encrypted, err := replicaCommon.MKEMNikeScheme.EnvelopeReply(ctidhFixtures[3].Priv, ctidhFixtures[5].Pub, padded)
	require.NoError(t, err)
	return &pigeonhole.CourierEnvelopeReply{
		ReplyType:  pigeonhole.ReplyTypePayload,
		PayloadLen: uint32(len(encrypted.Envelope)),
		Payload:    encrypted.Envelope,
	}
}

func (h *shardReadHarness) answers() []*thin.StartResendingEncryptedMessageReply {
	h.conn.sendQueueMu.Lock()
	defer h.conn.sendQueueMu.Unlock()
	var answers []*thin.StartResendingEncryptedMessageReply
	for _, r := range h.conn.sendQueue {
		if r.StartResendingEncryptedMessageReply != nil {
			answers = append(answers, r.StartResendingEncryptedMessageReply)
		}
	}
	return answers
}

// TestNoRetryReadWaitsForHolderSuccess follows a read sent to both shard
// holders when one answers box-not-found before the other answers with
// the box. The courier ACKs the poll while it holds back the
// box-not-found, so a NoRetryOnBoxIDNotFound read keeps polling and then
// returns the stored message rather than reporting it missing.
func TestNoRetryReadWaitsForHolderSuccess(t *testing.T) {
	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	pos := writeCap.Start()
	index, err := pos.Index().MarshalBinary()
	require.NoError(t, err)
	message := []byte("stored on one shard holder")
	padded, err := pigeonhole.CreatePaddedPayload(message, len(message)+4)
	require.NoError(t, err)
	box, err := pigeonhole.Seal(pos, padded)
	require.NoError(t, err)

	h := newShardReadHarness(t, writeCap.ReadCap(), index, true)

	h.deliver(&pigeonhole.CourierEnvelopeReply{ReplyType: pigeonhole.ReplyTypeACK})
	require.Empty(t, h.answers(), "an ACK must not end a NoRetryOnBoxIDNotFound read")
	require.Equal(t, 2, arqTracked(h.d, h.m))
	require.Equal(t, ARQStateACKReceived, h.m.State)

	h.deliver(h.readReply(&pigeonhole.ReplicaReadReply{
		BoxID:      box.BoxID,
		Signature:  box.Signature,
		PayloadLen: box.PayloadLen,
		Payload:    box.Payload,
	}))
	answers := h.answers()
	require.Len(t, answers, 1)
	require.Equal(t, thin.ThinClientSuccess, answers[0].ErrorCode)
	require.Equal(t, message, answers[0].Plaintext)
}

// TestNoRetryReadReportsServedNotFound shows what the courier's hold
// protects against: a box-not-found it serves ends a
// NoRetryOnBoxIDNotFound read at once.
func TestNoRetryReadReportsServedNotFound(t *testing.T) {
	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	index, err := writeCap.Start().Index().MarshalBinary()
	require.NoError(t, err)

	h := newShardReadHarness(t, writeCap.ReadCap(), index, true)
	h.deliver(h.readReply(&pigeonhole.ReplicaReadReply{ErrorCode: pigeonhole.ReplicaErrorBoxIDNotFound}))
	answers := h.answers()
	require.Len(t, answers, 1)
	require.Equal(t, pigeonhole.ReplicaErrorBoxIDNotFound, answers[0].ErrorCode)
}
