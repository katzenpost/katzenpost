// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/thin"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

func plainARQRequest(t *testing.T, d *Daemon, appID *[AppIDLength]byte, payload []byte) (*Request, *[32]byte) {
	t.Helper()
	_, doc := d.client.CurrentDocument()
	require.NotNil(t, doc)
	dest := hash.Sum256(doc.ServiceNodes[0].IdentityKey)
	messageID := new([32]byte)
	_, err := rand.Reader.Read(messageID[:])
	require.NoError(t, err)
	queryID := new([thin.QueryIDLength]byte)
	_, err = rand.Reader.Read(queryID[:])
	require.NoError(t, err)
	return &Request{
		AppID: appID,
		StartResendingMessage: &thin.StartResendingMessage{
			QueryID:           queryID,
			MessageID:         messageID,
			DestinationIdHash: &dest,
			RecipientQueueID:  []byte("voucher_router"),
			Payload:           payload,
		},
	}, messageID
}

func plainARQEntry(t *testing.T, d *Daemon, messageID *[32]byte) *ARQMessage {
	t.Helper()
	d.replyLock.Lock()
	defer d.replyLock.Unlock()
	surbID, ok := d.arqEnvelopeHashMap[*messageID]
	if !ok {
		return nil
	}
	m := d.arqSurbIDMap[*surbID]
	require.NotNil(t, m, "the MessageID map and the SURB ID map agree")
	return m
}

func awaitPacket(t *testing.T, packetCh chan []byte) []byte {
	t.Helper()
	select {
	case pkt := <-packetCh:
		return pkt
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for packet send")
		return nil
	}
}

func TestStartResendingMessage_FullPipeline(t *testing.T) {
	d, _, appID, _, packetCh := setupFullClient(t)
	req, messageID := plainARQRequest(t, d, appID, []byte("route me"))

	d.startResendingMessage(req)
	require.NotEmpty(t, awaitPacket(t, packetCh))

	m := plainARQEntry(t, d, messageID)
	require.NotNil(t, m)
	require.Equal(t, ARQMessageTypePlain, m.MessageType)
	require.Equal(t, []byte("route me"), m.Payload)
	require.Equal(t, req.StartResendingMessage.DestinationIdHash, m.DestinationIdHash)
	require.NotNil(t, m.SURBID)
	require.NotEmpty(t, m.SURBDecryptionKeys)
}

func TestStartResendingMessage_ResendRotatesSURB(t *testing.T) {
	d, _, appID, _, packetCh := setupFullClient(t)
	req, messageID := plainARQRequest(t, d, appID, []byte("again"))
	d.startResendingMessage(req)
	first := awaitPacket(t, packetCh)

	m := plainARQEntry(t, d, messageID)
	require.NotNil(t, m)
	oldSURB := *m.SURBID

	// A retransmission is what the scheduler runs on a Poisson tick after
	// enqueueResend hands it the SURB ID.
	d.arqDoResend(m.SURBID)
	second := awaitPacket(t, packetCh)
	require.NotEqual(t, first, second, "every transmission has a fresh SURB")

	m = plainARQEntry(t, d, messageID)
	require.NotNil(t, m)
	require.NotEqual(t, oldSURB, *m.SURBID)
	require.Equal(t, uint32(1), m.Retransmissions)
	require.Equal(t, []byte("again"), m.Payload, "the payload never changes")

	d.replyLock.Lock()
	_, stale := d.arqSurbIDMap[oldSURB]
	d.replyLock.Unlock()
	require.False(t, stale, "the old SURB ID is retired")
}

func TestStartResendingMessage_ReplyEndsExchange(t *testing.T) {
	d, _, appID, responseCh, packetCh := setupFullClient(t)
	req, messageID := plainARQRequest(t, d, appID, []byte("ping"))
	d.startResendingMessage(req)
	awaitPacket(t, packetCh)

	m := plainARQEntry(t, d, messageID)
	require.NotNil(t, m)
	conn := d.listener.getConnection(appID)
	d.handlePlainARQReply(m, []byte("pong"), conn)

	reply := awaitResponse(t, responseCh).StartResendingMessageReply
	require.NotNil(t, reply)
	require.Equal(t, thin.ThinClientSuccess, reply.ErrorCode)
	require.Equal(t, []byte("pong"), reply.Payload)
	require.Equal(t, req.StartResendingMessage.QueryID, reply.QueryID)
	require.Equal(t, messageID, reply.MessageID)
	require.Nil(t, plainARQEntry(t, d, messageID), "the exchange is gone")

	// A late duplicate reply answers nothing.
	d.handlePlainARQReply(m, []byte("pong"), conn)
	select {
	case r := <-responseCh:
		t.Fatalf("unexpected second answer: %+v", r)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestCancelResendingMessage(t *testing.T) {
	d, _, appID, responseCh, packetCh := setupFullClient(t)
	req, messageID := plainARQRequest(t, d, appID, []byte("never mind"))
	d.startResendingMessage(req)
	awaitPacket(t, packetCh)

	cancelQuery := &[thin.QueryIDLength]byte{0x77}
	d.cancelResendingMessage(&Request{
		AppID: appID,
		CancelResendingMessage: &thin.CancelResendingMessage{
			QueryID:   cancelQuery,
			MessageID: messageID,
		},
	})

	cancelled := awaitResponse(t, responseCh).StartResendingMessageReply
	require.NotNil(t, cancelled)
	require.Equal(t, thin.ThinClientErrorStartResendingCancelled, cancelled.ErrorCode)
	require.Equal(t, req.StartResendingMessage.QueryID, cancelled.QueryID)

	ack := awaitResponse(t, responseCh).CancelResendingMessageReply
	require.NotNil(t, ack)
	require.Equal(t, thin.ThinClientSuccess, ack.ErrorCode)
	require.Equal(t, cancelQuery, ack.QueryID)
	require.Nil(t, plainARQEntry(t, d, messageID))
}

func TestCancelResendingMessageLeavesOtherOperations(t *testing.T) {
	d, _, appID, responseCh, _ := setupFullClient(t)
	m := &ARQMessage{AppID: appID, SURBID: &[sphinxConstants.SURBIDLength]byte{0x02}, EnvelopeHash: &[32]byte{0x01}}
	d.replyLock.Lock()
	d.arqSurbIDMap[*m.SURBID] = m
	d.arqEnvelopeHashMap[*m.EnvelopeHash] = m.SURBID
	d.replyLock.Unlock()

	d.cancelResendingMessage(&Request{
		AppID: appID,
		CancelResendingMessage: &thin.CancelResendingMessage{
			QueryID:   &[thin.QueryIDLength]byte{0x01},
			MessageID: m.EnvelopeHash,
		},
	})
	ack := awaitResponse(t, responseCh).CancelResendingMessageReply
	require.NotNil(t, ack)
	require.NotNil(t, plainARQEntry(t, d, m.EnvelopeHash), "a pigeonhole operation is not a plain ARQ")
}

func TestStartResendingMessageRejects(t *testing.T) {
	d, _, appID, responseCh, packetCh := setupFullClient(t)

	tooBig, _ := plainARQRequest(t, d, appID, make([]byte, d.client.geo.UserForwardPayloadLength+1))
	noID, _ := plainARQRequest(t, d, appID, []byte("x"))
	noID.StartResendingMessage.MessageID = nil
	noDest, _ := plainARQRequest(t, d, appID, []byte("x"))
	noDest.StartResendingMessage.DestinationIdHash = nil

	for _, req := range []*Request{tooBig, noID, noDest} {
		d.startResendingMessage(req)
		reply := awaitResponse(t, responseCh).StartResendingMessageReply
		require.NotNil(t, reply)
		require.Equal(t, thin.ThinClientErrorInvalidRequest, reply.ErrorCode)
	}

	// A MessageID already in flight is refused.
	first, messageID := plainARQRequest(t, d, appID, []byte("once"))
	d.startResendingMessage(first)
	awaitPacket(t, packetCh)
	dup, _ := plainARQRequest(t, d, appID, []byte("twice"))
	dup.StartResendingMessage.MessageID = messageID
	d.startResendingMessage(dup)
	reply := awaitResponse(t, responseCh).StartResendingMessageReply
	require.NotNil(t, reply)
	require.Equal(t, thin.ThinClientErrorInvalidRequest, reply.ErrorCode)
	require.Equal(t, []byte("once"), plainARQEntry(t, d, messageID).Payload)
}

func TestPlainARQRequestRouting(t *testing.T) {
	require.False(t, isLocalRequest(&Request{StartResendingMessage: &thin.StartResendingMessage{}}),
		"StartResendingMessage leaves on a Poisson tick")
	require.True(t, isLocalRequest(&Request{CancelResendingMessage: &thin.CancelResendingMessage{}}))
}
