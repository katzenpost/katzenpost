// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func vqPumpedClient(t *testing.T) (*ThinClient, net.Conn) {
	client, server := net.Pipe()
	tc := newHandshakeTestClient(t, client)
	done := make(chan struct{})
	go func() {
		drains := make(map[chan Event]struct{})
		for {
			select {
			case <-done:
				return
			case drain := <-tc.drainAdd:
				drains[drain] = struct{}{}
			case drain := <-tc.drainRemove:
				delete(drains, drain)
			}
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		close(done)
		server.Close()
		client.Close()
	})
	return tc, server
}

func vqHaltedClient(t *testing.T) *ThinClient {
	tc, _ := vqPumpedClient(t)
	tc.setConnected(true)
	tc.Halt()
	return tc
}

func vqBrokenClient(t *testing.T) *ThinClient {
	tc, server := vqPumpedClient(t)
	tc.setConnected(true)
	server.Close()
	tc.conn.Close()
	return tc
}

func vqServeReplies(t *testing.T, server net.Conn, replies func(*Request) []*Response) {
	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}
		for _, response := range replies(req) {
			sendResponse(t, server, response)
		}
	}()
}

type vqQueryProbe struct {
	name    string
	queryID func(*Request) *[QueryIDLength]byte
	reply   func(*[QueryIDLength]byte, uint8) *Response
	call    func(*ThinClient) error
}

func vqQueryProbes() []vqQueryProbe {
	return []vqQueryProbe{
		{
			name:    "VoucherMint",
			queryID: func(req *Request) *[QueryIDLength]byte { return req.VoucherMint.QueryID },
			reply: func(id *[QueryIDLength]byte, code uint8) *Response {
				return &Response{VoucherMintReply: &VoucherMintReply{QueryID: id, ErrorCode: code}}
			},
			call: func(tc *ThinClient) error {
				_, err := tc.VoucherMint([]byte("write cap"), "alice")
				return err
			},
		},
		{
			name:    "VoucherInduct",
			queryID: func(req *Request) *[QueryIDLength]byte { return req.VoucherInduct.QueryID },
			reply: func(id *[QueryIDLength]byte, code uint8) *Response {
				return &Response{VoucherInductReply: &VoucherInductReply{QueryID: id, ErrorCode: code}}
			},
			call: func(tc *ThinClient) error {
				_, err := tc.VoucherInduct([]byte("voucher"), []byte("payload"), []byte("who"))
				return err
			},
		},
		{
			name:    "VoucherOpen",
			queryID: func(req *Request) *[QueryIDLength]byte { return req.VoucherOpen.QueryID },
			reply: func(id *[QueryIDLength]byte, code uint8) *Response {
				return &Response{VoucherOpenReply: &VoucherOpenReply{QueryID: id, ErrorCode: code}}
			},
			call: func(tc *ThinClient) error {
				_, err := tc.VoucherOpen([]byte("secret"), []byte("sealed"), []byte("write cap"))
				return err
			},
		},
		{
			name:    "VoucherDeriveStream",
			queryID: func(req *Request) *[QueryIDLength]byte { return req.VoucherDeriveStream.QueryID },
			reply: func(id *[QueryIDLength]byte, code uint8) *Response {
				return &Response{VoucherDeriveStreamReply: &VoucherDeriveStreamReply{QueryID: id, ErrorCode: code}}
			},
			call: func(tc *ThinClient) error {
				_, err := tc.VoucherDeriveStream([]byte("voucher"))
				return err
			},
		},
		{
			name:    "GetPKIDocumentRaw",
			queryID: func(req *Request) *[QueryIDLength]byte { return req.GetPKIDocument.QueryID },
			reply: func(id *[QueryIDLength]byte, code uint8) *Response {
				return &Response{GetPKIDocumentReply: &GetPKIDocumentReply{QueryID: id, ErrorCode: code}}
			},
			call: func(tc *ThinClient) error {
				_, _, err := tc.GetPKIDocumentRaw(0)
				return err
			},
		},
		{
			name:    "GetDirectoryAuthorities",
			queryID: func(req *Request) *[QueryIDLength]byte { return req.GetDirectoryAuthorities.QueryID },
			reply: func(id *[QueryIDLength]byte, code uint8) *Response {
				return &Response{GetDirectoryAuthoritiesReply: &GetDirectoryAuthoritiesReply{QueryID: id, ErrorCode: code}}
			},
			call: func(tc *ThinClient) error {
				_, err := tc.GetDirectoryAuthorities()
				return err
			},
		},
	}
}

func TestVqQueryMethodsSkipRepliesThatAreNotTheirOwn(t *testing.T) {
	for _, probe := range vqQueryProbes() {
		t.Run(probe.name, func(t *testing.T) {
			tc, server := dialFakeDaemon(t)
			doc := pkiDocResponse(t, 402)
			foreign := tc.NewQueryID()
			vqServeReplies(t, server, func(req *Request) []*Response {
				return []*Response{
					probe.reply(nil, ThinClientSuccess),
					probe.reply(foreign, ThinClientSuccess),
					{ConnectionStatusEvent: &ConnectionStatusEvent{IsConnected: true}},
					doc,
					{MessageIDGarbageCollected: &MessageIDGarbageCollected{}},
					probe.reply(probe.queryID(req), ThinClientSuccess),
				}
			})
			require.NoError(t, probe.call(tc))
			require.True(t, tc.IsConnected())
		})
	}
}

func TestVqQueryMethodsReturnTheDaemonErrorCode(t *testing.T) {
	for _, probe := range vqQueryProbes() {
		t.Run(probe.name, func(t *testing.T) {
			tc, server := dialFakeDaemon(t)
			vqServeReplies(t, server, func(req *Request) []*Response {
				return []*Response{probe.reply(probe.queryID(req), 1)}
			})
			require.Error(t, probe.call(tc))
		})
	}
}

func TestVqQueryMethodsStopOnHalt(t *testing.T) {
	for _, probe := range vqQueryProbes() {
		t.Run(probe.name, func(t *testing.T) {
			tc := vqHaltedClient(t)
			require.ErrorIs(t, probe.call(tc), errHalting)
		})
	}
}

func TestVqQueryMethodsReturnTheWriteFailure(t *testing.T) {
	for _, probe := range vqQueryProbes() {
		t.Run(probe.name, func(t *testing.T) {
			tc := vqBrokenClient(t)
			require.Error(t, probe.call(tc))
		})
	}
}

func vqSimpleResponses() []*Response {
	return []*Response{
		{SessionTokenReply: &SessionTokenReply{}},
		{MessageIDGarbageCollected: &MessageIDGarbageCollected{}},
		{NewKeypairReply: &NewKeypairReply{}},
		{EncryptReadReply: &EncryptReadReply{}},
		{EncryptWriteReply: &EncryptWriteReply{}},
		{StartResendingEncryptedMessageReply: &StartResendingEncryptedMessageReply{}},
		{CancelResendingEncryptedMessageReply: &CancelResendingEncryptedMessageReply{}},
		{StartResendingCopyCommandReply: &StartResendingCopyCommandReply{}},
		{CancelResendingCopyCommandReply: &CancelResendingCopyCommandReply{}},
		{NextMessageBoxIndexReply: &NextMessageBoxIndexReply{}},
		{GetMessageBoxIndexCounterReply: &GetMessageBoxIndexCounterReply{}},
		{GetPKIDocumentReply: &GetPKIDocumentReply{}},
		{GetDirectoryAuthoritiesReply: &GetDirectoryAuthoritiesReply{}},
		{CreateCourierEnvelopesFromPayloadReply: &CreateCourierEnvelopesFromPayloadReply{}},
		{CreateCourierEnvelopesFromPayloadsReply: &CreateCourierEnvelopesFromPayloadsReply{}},
		{CreateCourierEnvelopesFromTombstoneRangeReply: &CreateCourierEnvelopesFromTombstoneRangeReply{}},
		{VoucherMintReply: &VoucherMintReply{}},
		{VoucherInductReply: &VoucherInductReply{}},
		{VoucherOpenReply: &VoucherOpenReply{}},
		{VoucherDeriveStreamReply: &VoucherDeriveStreamReply{}},
	}
}

func TestVqDispatchMessageRoutesEveryEventType(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	tc := newHandshakeTestClient(t, client)
	tc.eventSink = make(chan Event, 128)

	arqSent := [MessageIDLength]byte{1}
	arqReply := [MessageIDLength]byte{2}
	unknown := [MessageIDLength]byte{3}
	sentWaitChan := make(chan error, 2)
	replyWaitChan := make(chan *MessageReplyEvent, 1)
	tc.sentWaitChanMap.Store(arqSent, sentWaitChan)
	tc.replyWaitChanMap.Store(arqReply, replyWaitChan)

	sphinxGeo, pigeonGeo := newTestGeometries()
	messages := append(vqSimpleResponses(),
		&Response{ConnectionStatusEvent: &ConnectionStatusEvent{
			IsConnected: true, SphinxGeometry: sphinxGeo, PigeonholeGeometry: pigeonGeo,
		}},
		pkiDocResponse(t, 500),
		&Response{NewPKIDocumentEvent: &NewPKIDocumentEvent{Payload: []byte{0xff}}},
		&Response{MessageSentEvent: &MessageSentEvent{}},
		&Response{MessageSentEvent: &MessageSentEvent{MessageID: &unknown}},
		&Response{MessageSentEvent: &MessageSentEvent{MessageID: &arqSent}},
		&Response{MessageSentEvent: &MessageSentEvent{MessageID: &arqSent, Err: "send failed"}},
		&Response{MessageReplyEvent: &MessageReplyEvent{Payload: []byte("payload")}},
		&Response{MessageReplyEvent: &MessageReplyEvent{}},
		&Response{MessageReplyEvent: &MessageReplyEvent{ErrorCode: 1}},
		&Response{MessageReplyEvent: &MessageReplyEvent{MessageID: &unknown, Payload: []byte("payload")}},
		&Response{MessageReplyEvent: &MessageReplyEvent{MessageID: &arqReply, Payload: []byte("payload")}},
		&Response{},
	)
	for _, message := range messages {
		require.True(t, tc.dispatchMessage(message))
	}

	require.NoError(t, <-sentWaitChan)
	require.Error(t, <-sentWaitChan)
	require.NotNil(t, <-replyWaitChan)
	require.True(t, tc.IsConnected())
	require.Equal(t, sphinxGeo, tc.GetSphinxGeometry())
	require.Equal(t, pigeonGeo, tc.GetPigeonholeGeometry())
	require.Contains(t, tc.pkiDocCache, uint64(500))
}

func TestVqDispatchMessageStopsOnHalt(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	tc := newHandshakeTestClient(t, client)
	tc.eventSink = make(chan Event)

	arqSent := [MessageIDLength]byte{1}
	arqReply := [MessageIDLength]byte{2}
	tc.sentWaitChanMap.Store(arqSent, make(chan error))
	tc.replyWaitChanMap.Store(arqReply, make(chan *MessageReplyEvent))
	tc.Halt()

	messages := append(vqSimpleResponses(),
		&Response{ConnectionStatusEvent: &ConnectionStatusEvent{IsConnected: true}},
		pkiDocResponse(t, 501),
		&Response{MessageSentEvent: &MessageSentEvent{}},
		&Response{MessageSentEvent: &MessageSentEvent{MessageID: &arqSent}},
		&Response{MessageReplyEvent: &MessageReplyEvent{Payload: []byte("payload")}},
		&Response{MessageReplyEvent: &MessageReplyEvent{MessageID: &arqReply, Payload: []byte("payload")}},
	)
	for _, message := range messages {
		require.False(t, tc.dispatchMessage(message))
	}
}

type vqShortWriteConn struct {
	net.Conn
}

func (c vqShortWriteConn) Write(b []byte) (int, error) {
	return len(b) - 1, nil
}

func TestVqWriteMessageRejectsAPayloadWithoutGeometry(t *testing.T) {
	tc, _ := vqPumpedClient(t)
	tc.sphinxGeo = nil
	err := tc.writeMessage(&Request{SendMessage: &SendMessage{Payload: []byte("payload")}})
	require.Error(t, err)
}

func TestVqWriteMessageReportsAShortWrite(t *testing.T) {
	tc, _ := vqPumpedClient(t)
	tc.conn = vqShortWriteConn{Conn: tc.conn}
	err := tc.writeMessage(&Request{SessionToken: &SessionToken{}})
	require.Error(t, err)
}

func TestVqReadMessageReportsATruncatedFrame(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	tc := newHandshakeTestClient(t, client)
	go func() {
		if _, err := server.Write([]byte{0, 0, 0, 8}); err != nil {
			return
		}
		server.Close()
	}()
	_, err := tc.readMessage()
	require.Error(t, err)
}

func TestVqNewMessageIDAndNewQueryIDAreRandom(t *testing.T) {
	tc, _ := vqPumpedClient(t)
	require.NotEqual(t, tc.NewMessageID(), tc.NewMessageID())
	require.NotEqual(t, tc.NewQueryID(), tc.NewQueryID())
	require.NotNil(t, tc.NewSURBID())
}

func TestVqBlockingSendMessageWithResultReturnsTheWriteFailure(t *testing.T) {
	tc := vqBrokenClient(t)
	res, err := tc.BlockingSendMessageWithResult(
		context.Background(), []byte("payload"), &[32]byte{}, []byte("queue"), 0)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestVqBlockingSendMessageWithResultStopsOnHalt(t *testing.T) {
	tc := vqHaltedClient(t)
	res, err := tc.BlockingSendMessageWithResult(
		context.Background(), []byte("payload"), &[32]byte{}, []byte("queue"), 0)
	require.ErrorIs(t, err, errHalting)
	require.NotNil(t, res)
}

func TestVqBlockingSendMessageWithResultReportsASendFailure(t *testing.T) {
	tc, server := dialFakeDaemon(t)
	vqServeReplies(t, server, func(req *Request) []*Response {
		return []*Response{{MessageSentEvent: &MessageSentEvent{
			SURBID: req.SendMessage.SURBID, Err: "no path",
		}}}
	})
	res, err := tc.BlockingSendMessageWithResult(
		context.Background(), []byte("payload"), &[32]byte{}, []byte("queue"), 0)
	require.ErrorIs(t, err, ErrSendFailed)
	require.NotNil(t, res)
}

func TestVqBlockingSendMessageWithResultGivesUpOnceTheReplyIsOverdue(t *testing.T) {
	tc, server := dialFakeDaemon(t)
	vqServeReplies(t, server, func(req *Request) []*Response {
		return []*Response{{MessageSentEvent: &MessageSentEvent{
			SURBID:   req.SendMessage.SURBID,
			SentAt:   time.Now().Add(-time.Minute),
			ReplyETA: time.Second,
		}}}
	})
	res, err := tc.BlockingSendMessageWithResult(
		context.Background(), []byte("payload"), &[32]byte{}, []byte("queue"), time.Millisecond)
	require.ErrorIs(t, err, ErrReplyOverdue)
	require.NotNil(t, res)
	require.Equal(t, time.Second, res.ReplyETA)
}
