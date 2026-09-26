// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

const phDrainWait = 5 * time.Second

func phSendResponse(conn net.Conn, response *Response) {
	blob, err := cbor.Marshal(response)
	if err != nil {
		return
	}
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint32(prefix, uint32(len(blob)))
	_, _ = conn.Write(append(prefix, blob...))
}

type phCase struct {
	name  string
	qid   func(*Request) *[QueryIDLength]byte
	reply func(*[QueryIDLength]byte, uint8) *Response
	call  func(*ThinClient) error
}

func phCases(t *testing.T) []phCase {
	t.Helper()

	writeCap := newTestWriteCap(t)
	readCap := newTestReadCap(t)
	index := newTestMessageBoxIndex(t)
	envelopeHash := &[32]byte{0x11}
	replyIndex := uint8(0)
	seed := make([]byte, 32)
	payload := []byte("payload")

	return []phCase{
		{
			name: "NewKeypair",
			qid:  func(req *Request) *[QueryIDLength]byte { return req.NewKeypair.QueryID },
			reply: func(q *[QueryIDLength]byte, code uint8) *Response {
				return &Response{NewKeypairReply: &NewKeypairReply{QueryID: q, ErrorCode: code}}
			},
			call: func(tc *ThinClient) error {
				_, _, _, err := tc.NewKeypair(seed)
				return err
			},
		},
		{
			name: "EncryptRead",
			qid:  func(req *Request) *[QueryIDLength]byte { return req.EncryptRead.QueryID },
			reply: func(q *[QueryIDLength]byte, code uint8) *Response {
				return &Response{EncryptReadReply: &EncryptReadReply{QueryID: q, ErrorCode: code}}
			},
			call: func(tc *ThinClient) error {
				_, _, _, _, err := tc.EncryptRead(readCap, index)
				return err
			},
		},
		{
			name: "EncryptWrite",
			qid:  func(req *Request) *[QueryIDLength]byte { return req.EncryptWrite.QueryID },
			reply: func(q *[QueryIDLength]byte, code uint8) *Response {
				return &Response{EncryptWriteReply: &EncryptWriteReply{QueryID: q, ErrorCode: code}}
			},
			call: func(tc *ThinClient) error {
				_, _, _, _, err := tc.EncryptWrite(payload, writeCap, index)
				return err
			},
		},
		{
			name: "StartResendingEncryptedMessage",
			qid: func(req *Request) *[QueryIDLength]byte {
				return req.StartResendingEncryptedMessage.QueryID
			},
			reply: func(q *[QueryIDLength]byte, code uint8) *Response {
				return &Response{StartResendingEncryptedMessageReply: &StartResendingEncryptedMessageReply{
					QueryID: q, ErrorCode: code,
				}}
			},
			call: func(tc *ThinClient) error {
				_, err := tc.StartResendingEncryptedMessage(readCap, nil, nil, &replyIndex, nil, nil, envelopeHash)
				return err
			},
		},
		{
			name: "CancelResendingEncryptedMessage",
			qid: func(req *Request) *[QueryIDLength]byte {
				return req.CancelResendingEncryptedMessage.QueryID
			},
			reply: func(q *[QueryIDLength]byte, code uint8) *Response {
				return &Response{CancelResendingEncryptedMessageReply: &CancelResendingEncryptedMessageReply{
					QueryID: q, ErrorCode: code,
				}}
			},
			call: func(tc *ThinClient) error {
				return tc.CancelResendingEncryptedMessage(envelopeHash)
			},
		},
		{
			name: "StartResendingCopyCommand",
			qid:  func(req *Request) *[QueryIDLength]byte { return req.StartResendingCopyCommand.QueryID },
			reply: func(q *[QueryIDLength]byte, code uint8) *Response {
				return &Response{StartResendingCopyCommandReply: &StartResendingCopyCommandReply{
					QueryID: q, ErrorCode: code,
				}}
			},
			call: func(tc *ThinClient) error {
				return tc.StartResendingCopyCommand(writeCap)
			},
		},
		{
			name: "CancelResendingCopyCommand",
			qid:  func(req *Request) *[QueryIDLength]byte { return req.CancelResendingCopyCommand.QueryID },
			reply: func(q *[QueryIDLength]byte, code uint8) *Response {
				return &Response{CancelResendingCopyCommandReply: &CancelResendingCopyCommandReply{
					QueryID: q, ErrorCode: code,
				}}
			},
			call: func(tc *ThinClient) error {
				return tc.CancelResendingCopyCommand(envelopeHash)
			},
		},
		{
			name: "NextMessageBoxIndex",
			qid:  func(req *Request) *[QueryIDLength]byte { return req.NextMessageBoxIndex.QueryID },
			reply: func(q *[QueryIDLength]byte, code uint8) *Response {
				return &Response{NextMessageBoxIndexReply: &NextMessageBoxIndexReply{QueryID: q, ErrorCode: code}}
			},
			call: func(tc *ThinClient) error {
				_, err := tc.NextMessageBoxIndex(index)
				return err
			},
		},
		{
			name: "GetMessageBoxIndexCounter",
			qid:  func(req *Request) *[QueryIDLength]byte { return req.GetMessageBoxIndexCounter.QueryID },
			reply: func(q *[QueryIDLength]byte, code uint8) *Response {
				return &Response{GetMessageBoxIndexCounterReply: &GetMessageBoxIndexCounterReply{
					QueryID: q, ErrorCode: code, Counter: 3,
				}}
			},
			call: func(tc *ThinClient) error {
				_, err := tc.GetMessageBoxIndexCounter(index)
				return err
			},
		},
		{
			name: "CreateCourierEnvelopesFromPayload",
			qid: func(req *Request) *[QueryIDLength]byte {
				return req.CreateCourierEnvelopesFromPayload.QueryID
			},
			reply: func(q *[QueryIDLength]byte, code uint8) *Response {
				return &Response{CreateCourierEnvelopesFromPayloadReply: &CreateCourierEnvelopesFromPayloadReply{
					QueryID: q, ErrorCode: code,
				}}
			},
			call: func(tc *ThinClient) error {
				_, _, err := tc.CreateCourierEnvelopesFromPayload(payload, writeCap, index, true, true)
				return err
			},
		},
		{
			name: "CreateCourierEnvelopesFromMultiPayload",
			qid: func(req *Request) *[QueryIDLength]byte {
				return req.CreateCourierEnvelopesFromPayloads.QueryID
			},
			reply: func(q *[QueryIDLength]byte, code uint8) *Response {
				return &Response{CreateCourierEnvelopesFromPayloadsReply: &CreateCourierEnvelopesFromPayloadsReply{
					QueryID: q, ErrorCode: code,
				}}
			},
			call: func(tc *ThinClient) error {
				_, err := tc.CreateCourierEnvelopesFromMultiPayload([]DestinationPayload{{
					Payload:    payload,
					WriteCap:   writeCap,
					StartIndex: index,
				}}, true, true, nil)
				return err
			},
		},
		{
			name: "CreateCourierEnvelopesFromTombstoneRange",
			qid: func(req *Request) *[QueryIDLength]byte {
				return req.CreateCourierEnvelopesFromTombstoneRange.QueryID
			},
			reply: func(q *[QueryIDLength]byte, code uint8) *Response {
				return &Response{CreateCourierEnvelopesFromTombstoneRangeReply: &CreateCourierEnvelopesFromTombstoneRangeReply{
					QueryID: q, ErrorCode: code,
				}}
			},
			call: func(tc *ThinClient) error {
				_, _, _, err := tc.CreateCourierEnvelopesFromTombstoneRange(writeCap, index, 1, true, true, nil)
				return err
			},
		},
		{
			name: "TombstoneRange",
			call: func(tc *ThinClient) error {
				_, err := tc.TombstoneRange(writeCap, index, 1)
				return err
			},
		},
	}
}

func TestPhWrappersIgnoreRepliesThatAreNotTheirOwn(t *testing.T) {
	for _, c := range phCases(t) {
		if c.qid == nil {
			continue
		}
		c := c
		t.Run(c.name, func(t *testing.T) {
			tc, server := dialFakeDaemon(t)
			document := pkiDocResponse(t, 402)
			go func() {
				req, err := readRequest(server)
				if err != nil {
					return
				}
				queryID := c.qid(req)
				mismatched := new([QueryIDLength]byte)
				copy(mismatched[:], queryID[:])
				mismatched[0] ^= 0xff
				phSendResponse(server, c.reply(nil, ThinClientSuccess))
				phSendResponse(server, c.reply(mismatched, ThinClientSuccess))
				phSendResponse(server, &Response{
					ConnectionStatusEvent: &ConnectionStatusEvent{IsConnected: true},
				})
				phSendResponse(server, document)
				phSendResponse(server, &Response{
					MessageIDGarbageCollected: &MessageIDGarbageCollected{
						MessageID: new([MessageIDLength]byte),
					},
				})
				phSendResponse(server, c.reply(queryID, ThinClientSuccess))
			}()
			require.NoError(t, c.call(tc))
		})
	}
}

func TestPhWrappersReturnTheDaemonErrorCode(t *testing.T) {
	for _, c := range phCases(t) {
		if c.qid == nil {
			continue
		}
		c := c
		t.Run(c.name, func(t *testing.T) {
			tc, server := dialFakeDaemon(t)
			go func() {
				req, err := readRequest(server)
				if err != nil {
					return
				}
				phSendResponse(server, c.reply(c.qid(req), 1))
			}()
			require.Error(t, c.call(tc))
		})
	}
}

func TestPhWrappersReportAWriteFailure(t *testing.T) {
	tc, _ := setupMockDaemon(t)
	tc.setConnected(true)
	require.NoError(t, tc.conn.Close())

	for _, c := range phCases(t) {
		c := c
		t.Run(c.name, func(t *testing.T) {
			require.Error(t, c.call(tc))
		})
	}
}

func TestPhWrappersStopWhenTheClientHalts(t *testing.T) {
	for _, c := range phCases(t) {
		c := c
		t.Run(c.name, func(t *testing.T) {
			tc, server := setupMockDaemon(t)
			tc.setConnected(true)
			go func() {
				if _, err := readRequest(server); err != nil {
					return
				}
				tc.Halt()
				select {
				case <-tc.drainRemove:
				case <-time.After(phDrainWait):
				}
			}()
			require.Error(t, c.call(tc))
		})
	}
}
