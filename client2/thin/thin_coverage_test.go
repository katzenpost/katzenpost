// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2/config"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
	"github.com/stretchr/testify/require"
)

func TestSendMessageConnected(t *testing.T) {
	tc, server := setupMockDaemon(t)
	tc.connMu.Lock()
	tc.isConnected = true
	tc.connMu.Unlock()

	go func() {
		readRequest(server)
	}()

	surbID := &[sConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbID[:])
	require.NoError(t, err)

	err = tc.SendMessage(surbID, []byte("hello"), &[32]byte{}, []byte("queue"))
	require.NoError(t, err)
}

func TestSendMessageWithoutReplyConnected(t *testing.T) {
	tc, server := setupMockDaemon(t)
	tc.connMu.Lock()
	tc.isConnected = true
	tc.connMu.Unlock()

	go func() {
		readRequest(server)
	}()

	err := tc.SendMessageWithoutReply([]byte("hello"), &[32]byte{}, []byte("queue"))
	require.NoError(t, err)
}

func TestBlockingSendMessageSuccess(t *testing.T) {
	tc, server := setupMockDaemon(t)
	tc.connMu.Lock()
	tc.isConnected = true
	tc.connMu.Unlock()

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}
		surbID := req.SendMessage.SURBID

		sendResponse(t, server, &Response{
			MessageSentEvent: &MessageSentEvent{
				MessageID: &[MessageIDLength]byte{},
				SURBID:    surbID,
				SentAt:    time.Now(),
			},
		})

		sendResponse(t, server, &Response{
			MessageReplyEvent: &MessageReplyEvent{
				MessageID: &[MessageIDLength]byte{},
				SURBID:    surbID,
				Payload:   []byte("reply-payload"),
			},
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	reply, err := tc.BlockingSendMessage(ctx, []byte("hello"), &[32]byte{}, []byte("queue"))
	require.NoError(t, err)
	require.Equal(t, []byte("reply-payload"), reply)
}

func TestBlockingSendMessageIgnoresEventsAndMismatchedReplies(t *testing.T) {
	tc, server := setupMockDaemon(t)
	tc.connMu.Lock()
	tc.isConnected = true
	tc.connMu.Unlock()

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}
		surbID := req.SendMessage.SURBID

		// GC event (ignored)
		sendResponse(t, server, &Response{
			MessageIDGarbageCollected: &MessageIDGarbageCollected{
				MessageID: &[MessageIDLength]byte{1},
			},
		})

		// PKI doc event (ignored)
		doc := &cpki.Document{Epoch: 99}
		docBytes, _ := cbor.Marshal(doc)
		sendResponse(t, server, &Response{
			NewPKIDocumentEvent: &NewPKIDocumentEvent{Payload: docBytes},
		})

		// MessageSentEvent (ignored)
		sendResponse(t, server, &Response{
			MessageSentEvent: &MessageSentEvent{
				MessageID: &[MessageIDLength]byte{},
				SURBID:    surbID,
			},
		})

		// Mismatched SURB reply (ignored)
		sendResponse(t, server, &Response{
			MessageReplyEvent: &MessageReplyEvent{
				MessageID: &[MessageIDLength]byte{},
				SURBID:    &[sConstants.SURBIDLength]byte{0xFF},
				Payload:   []byte("wrong"),
			},
		})

		// Matching reply
		sendResponse(t, server, &Response{
			MessageReplyEvent: &MessageReplyEvent{
				MessageID: &[MessageIDLength]byte{},
				SURBID:    surbID,
				Payload:   []byte("correct"),
			},
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	reply, err := tc.BlockingSendMessage(ctx, []byte("hello"), &[32]byte{}, []byte("queue"))
	require.NoError(t, err)
	require.Equal(t, []byte("correct"), reply)
}

func TestTombstoneRangeSuccess(t *testing.T) {
	tc, server := setupMockDaemon(t)

	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	firstIdx := writeCap.GetFirstMessageBoxIndex()

	go func() {
		for i := 0; i < 2; i++ {
			req, err := readRequest(server)
			if err != nil {
				return
			}
			queryID := req.EncryptWrite.QueryID
			sendResponse(t, server, &Response{
				EncryptWriteReply: &EncryptWriteReply{
					QueryID:            queryID,
					MessageCiphertext:  []byte("ciphertext"),
					EnvelopeDescriptor: []byte("descriptor"),
					EnvelopeHash:       &[32]byte{byte(i)},
					ErrorCode:          ThinClientSuccess,
				},
			})
		}
	}()

	result, err := tc.TombstoneRange(writeCap, firstIdx, 2)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Envelopes, 2)
	require.NotNil(t, result.Next)
}

func TestTombstoneRangeNilWriteCap(t *testing.T) {
	tc := newTestThinClientNoConn(t)
	_, err := tc.TombstoneRange(nil, &bacap.MessageBoxIndex{}, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil writeCap")
}

func TestTombstoneRangeNilStart(t *testing.T) {
	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	tc := newTestThinClientNoConn(t)
	_, err = tc.TombstoneRange(writeCap, nil, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil start")
}

func TestEncryptReadHaltCh(t *testing.T) {
	tc, server := setupMockDaemon(t)

	readCap := createReadCap(t)
	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	mbi := writeCap.GetFirstMessageBoxIndex()

	go func() {
		readRequest(server)
		time.Sleep(50 * time.Millisecond)
		tc.Halt()
	}()

	_, _, _, err = tc.EncryptRead(readCap, mbi)
	require.Error(t, err)
}

func TestEncryptWriteHaltCh(t *testing.T) {
	tc, server := setupMockDaemon(t)

	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	mbi := writeCap.GetFirstMessageBoxIndex()

	go func() {
		readRequest(server)
		time.Sleep(50 * time.Millisecond)
		tc.Halt()
	}()

	_, _, _, err = tc.EncryptWrite([]byte("data"), writeCap, mbi)
	require.Error(t, err)
}

func TestStartResendingEncryptedMessageHaltCh(t *testing.T) {
	tc, server := setupMockDaemon(t)

	go func() {
		readRequest(server)
		time.Sleep(50 * time.Millisecond)
		tc.Halt()
	}()

	_, err := tc.StartResendingEncryptedMessage(
		nil, nil, nil, nil,
		[]byte("descriptor"), []byte("ciphertext"), &[32]byte{},
	)
	require.Error(t, err)
}

func TestNextMessageBoxIndexHaltCh(t *testing.T) {
	tc, server := setupMockDaemon(t)

	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	mbi := writeCap.GetFirstMessageBoxIndex()

	go func() {
		readRequest(server)
		time.Sleep(50 * time.Millisecond)
		tc.Halt()
	}()

	_, err = tc.NextMessageBoxIndex(mbi)
	require.Error(t, err)
}

func TestSetStreamBufferHaltCh(t *testing.T) {
	tc, server := setupMockDaemon(t)

	streamID := &[StreamIDLength]byte{}
	_, err := rand.Reader.Read(streamID[:])
	require.NoError(t, err)

	go func() {
		readRequest(server)
		time.Sleep(50 * time.Millisecond)
		tc.Halt()
	}()

	err = tc.SetStreamBuffer(streamID, []byte("buffer"))
	require.Error(t, err)
}

func TestCreateCourierEnvelopesFromPayloadHaltCh(t *testing.T) {
	tc, server := setupMockDaemon(t)

	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	mbi := writeCap.GetFirstMessageBoxIndex()

	go func() {
		readRequest(server)
		time.Sleep(50 * time.Millisecond)
		tc.Halt()
	}()

	_, _, err = tc.CreateCourierEnvelopesFromPayload(
		[]byte("data"), writeCap, mbi, true, true,
	)
	require.Error(t, err)
}

func TestStartResendingCopyCommandHaltCh(t *testing.T) {
	tc, server := setupMockDaemon(t)

	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)

	go func() {
		readRequest(server)
		time.Sleep(50 * time.Millisecond)
		tc.Halt()
	}()

	err = tc.StartResendingCopyCommand(writeCap)
	require.Error(t, err)
}

func TestCancelResendingEncryptedMessageHaltCh(t *testing.T) {
	tc, server := setupMockDaemon(t)

	go func() {
		readRequest(server)
		time.Sleep(50 * time.Millisecond)
		tc.Halt()
	}()

	err := tc.CancelResendingEncryptedMessage(&[32]byte{})
	require.Error(t, err)
}

func TestCancelResendingCopyCommandHaltCh(t *testing.T) {
	tc, server := setupMockDaemon(t)

	go func() {
		readRequest(server)
		time.Sleep(50 * time.Millisecond)
		tc.Halt()
	}()

	err := tc.CancelResendingCopyCommand(&[32]byte{})
	require.Error(t, err)
}

func TestStartResendingEncryptedMessageNoRetryHaltCh(t *testing.T) {
	tc, server := setupMockDaemon(t)

	go func() {
		readRequest(server)
		time.Sleep(50 * time.Millisecond)
		tc.Halt()
	}()

	_, err := tc.StartResendingEncryptedMessageNoRetry(
		nil, nil, nil, nil,
		[]byte("descriptor"), []byte("ciphertext"), &[32]byte{},
	)
	require.Error(t, err)
}

func TestStartResendingEncryptedMessageReturnBoxExistsHaltCh(t *testing.T) {
	tc, server := setupMockDaemon(t)

	go func() {
		readRequest(server)
		time.Sleep(50 * time.Millisecond)
		tc.Halt()
	}()

	_, err := tc.StartResendingEncryptedMessageReturnBoxExists(
		nil, nil, nil, nil,
		[]byte("descriptor"), []byte("ciphertext"), &[32]byte{},
	)
	require.Error(t, err)
}

func TestStartResendingCopyCommandWithCourierHaltCh(t *testing.T) {
	tc, server := setupMockDaemon(t)

	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)

	go func() {
		readRequest(server)
		time.Sleep(50 * time.Millisecond)
		tc.Halt()
	}()

	err = tc.StartResendingCopyCommandWithCourier(writeCap, &[32]byte{}, []byte("queue"))
	require.Error(t, err)
}

func TestCreateCourierEnvelopesFromMultiPayloadHaltCh(t *testing.T) {
	tc, server := setupMockDaemon(t)

	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	mbi := writeCap.GetFirstMessageBoxIndex()
	streamID := &[StreamIDLength]byte{}
	_, err = rand.Reader.Read(streamID[:])
	require.NoError(t, err)

	go func() {
		readRequest(server)
		time.Sleep(50 * time.Millisecond)
		tc.Halt()
	}()

	_, err = tc.CreateCourierEnvelopesFromMultiPayload(
		streamID,
		[]DestinationPayload{{Payload: []byte("data"), WriteCap: writeCap, StartIndex: mbi}},
		true,
	)
	require.Error(t, err)
}

func TestEncryptReadIgnoresConnectionStatus(t *testing.T) {
	tc, server := setupMockDaemon(t)

	readCap := createReadCap(t)
	writeCap, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	mbi := writeCap.GetFirstMessageBoxIndex()

	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}
		queryID := req.EncryptRead.QueryID

		// ConnectionStatusEvent first (ignored by EncryptRead)
		sendResponse(t, server, &Response{
			ConnectionStatusEvent: &ConnectionStatusEvent{IsConnected: true},
		})

		sendResponse(t, server, &Response{
			EncryptReadReply: &EncryptReadReply{
				QueryID:            queryID,
				MessageCiphertext:  []byte("ct"),
				NextMessageIndex:   []byte("nmi"),
				EnvelopeDescriptor: []byte("desc"),
				EnvelopeHash:       &[32]byte{},
				ErrorCode:          ThinClientSuccess,
			},
		})
	}()

	ct, _, _, err := tc.EncryptRead(readCap, mbi)
	require.NoError(t, err)
	require.Equal(t, []byte("ct"), ct)
}

func TestNewPKIDocumentEventStringValid(t *testing.T) {
	doc := &cpki.Document{Epoch: 77}
	payload, err := cbor.Marshal(doc)
	require.NoError(t, err)

	e := &NewPKIDocumentEvent{Payload: payload}
	s := e.String()
	require.Contains(t, s, "77")
}

func TestDialWithTCPListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		sendMockResponse(t, conn, &Response{
			ConnectionStatusEvent: &ConnectionStatusEvent{IsConnected: true},
		})

		doc := &cpki.Document{Epoch: 1}
		docBytes, _ := cbor.Marshal(doc)
		sendMockResponse(t, conn, &Response{
			NewPKIDocumentEvent: &NewPKIDocumentEvent{Payload: docBytes},
		})

		readRequest(conn)
		sendMockResponse(t, conn, &Response{
			SessionTokenReply: &SessionTokenReply{
				AppID:   make([]byte, 16),
				Resumed: false,
			},
		})

		time.Sleep(time.Second)
	}()

	nikeScheme := schemes.ByName("x25519")
	tc := NewThinClient(&Config{
		SphinxGeometry:     &geo.Geometry{UserForwardPayloadLength: 1000},
		PigeonholeGeometry: pigeonholeGeo.NewGeometry(1000, nikeScheme),
		Network:            "tcp",
		Address:            ln.Addr().String(),
	}, &config.Logging{Level: "DEBUG"})

	err = tc.Dial()
	require.NoError(t, err)
	tc.Close()
}

func createReadCap(t *testing.T) *bacap.ReadCap {
	t.Helper()
	wc, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	return wc.ReadCap()
}

// sendMockResponseRaw writes a CBOR response with length prefix (for use in TestDialWithTCPListener)
func sendMockResponseRaw(conn net.Conn, resp *Response) error {
	blob, err := cbor.Marshal(resp)
	if err != nil {
		return err
	}
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint32(prefix, uint32(len(blob)))
	_, err = conn.Write(append(prefix, blob...))
	return err
}
