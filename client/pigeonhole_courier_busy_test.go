// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/pigeonhole"
)

// courierErrorReply sends the courier envelope error code back through a
// real SURB and has the daemon handle it for a tracked write in the
// WaitingForACK state. It returns the daemon state afterwards.
func courierErrorReply(t *testing.T, errorCode uint8) (tracked int, answers int, armed int, state ARQState) {
	t.Helper()
	cfg, err := config.LoadFile(testClientTOML)
	require.NoError(t, err)
	sphinxInstance, err := sphinx.FromGeometry(cfg.SphinxGeometry)
	require.NoError(t, err)

	l := newSchedulerListener()
	d, armedCount := newARQTestDaemon(t, l)
	d.client = &Client{sphinx: sphinxInstance}
	conn := newTestIncomingConn(0x5B, 1, 1)
	l.testRegister(conn)

	nodes, path := createNikePathVector(require.New(t), cfg.SphinxGeometry.NIKEName, 5)
	surb, surbKeys, err := sphinxInstance.NewSURB(rand.Reader, path)
	require.NoError(t, err)

	m := trackARQMessage(d, conn.appID)
	m.SURBDecryptionKeys = surbKeys
	m.State = ARQStateWaitingForACK
	m.QueryID = &[thin.QueryIDLength]byte{0x66}

	courierReply := &pigeonhole.CourierQueryReply{
		EnvelopeReply: &pigeonhole.CourierEnvelopeReply{
			EnvelopeHash: *m.EnvelopeHash,
			ReplyType:    pigeonhole.ReplyTypeACK,
			ErrorCode:    errorCode,
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

	conn.sendQueueMu.Lock()
	for _, r := range conn.sendQueue {
		if r.StartResendingEncryptedMessageReply != nil {
			answers++
		}
	}
	conn.sendQueueMu.Unlock()
	return arqTracked(d, m), answers, d.arqTimerQueue.PushChLen() + int(armedCount.Load()), m.State
}

func TestARQCourierBusyIsRetried(t *testing.T) {
	tracked, answers, armed, state := courierErrorReply(t, pigeonhole.EnvelopeErrorCourierBusy)
	require.Equal(t, 2, tracked, "a busy courier must not end the operation")
	require.Zero(t, answers, "a busy courier must not be reported to the thin client")
	require.Equal(t, 1, armed, "the envelope must be scheduled for a resend")
	require.Equal(t, ARQStateWaitingForACK, state)
}

func TestARQCourierPermanentErrorIsReported(t *testing.T) {
	tracked, answers, _, _ := courierErrorReply(t, pigeonhole.EnvelopeErrorInvalidEpoch)
	require.Zero(t, tracked)
	require.Equal(t, 1, answers)
}

func TestIsTemporaryEnvelopeError(t *testing.T) {
	require.True(t, pigeonhole.IsTemporaryEnvelopeError(pigeonhole.EnvelopeErrorCourierBusy))
	for _, code := range []uint8{
		pigeonhole.EnvelopeErrorSuccess,
		pigeonhole.EnvelopeErrorInvalidEnvelope,
		pigeonhole.EnvelopeErrorCacheCorruption,
		pigeonhole.EnvelopeErrorPropagationError,
		pigeonhole.EnvelopeErrorInvalidEpoch,
		200,
	} {
		require.False(t, pigeonhole.IsTemporaryEnvelopeError(code), "code %d", code)
	}
}
