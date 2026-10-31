// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStartResendingMessageReturnsTheServiceReply(t *testing.T) {
	tc, server := dialFakeDaemon(t)
	dest := &[32]byte{0x01}
	serveOneReply(t, server, func(req *Request) *Response {
		r := req.StartResendingMessage
		require.NotNil(t, r)
		require.NotNil(t, r.MessageID)
		require.Equal(t, dest, r.DestinationIdHash)
		require.Equal(t, []byte("router"), r.RecipientQueueID)
		require.Equal(t, []byte("ping"), r.Payload)
		return &Response{StartResendingMessageReply: &StartResendingMessageReply{
			QueryID: r.QueryID, MessageID: r.MessageID, Payload: []byte("pong"),
		}}
	})
	reply, err := tc.StartResendingMessage(context.Background(), dest, []byte("router"), []byte("ping"))
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), reply)
}

func TestStartResendingMessageMapsTheDaemonError(t *testing.T) {
	tc, server := dialFakeDaemon(t)
	serveOneReply(t, server, func(req *Request) *Response {
		return &Response{StartResendingMessageReply: &StartResendingMessageReply{
			QueryID: req.StartResendingMessage.QueryID, ErrorCode: ThinClientErrorStartResendingCancelled,
		}}
	})
	_, err := tc.StartResendingMessage(context.Background(), &[32]byte{}, []byte("q"), []byte("p"))
	require.ErrorIs(t, err, ErrStartResendingCancelled)
}

func TestStartResendingMessageCancelsWhenContextEnds(t *testing.T) {
	tc, server := dialFakeDaemon(t)
	started := make(chan *[32]byte, 1)
	cancelled := make(chan *[32]byte, 1)
	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}
		started <- req.StartResendingMessage.MessageID
		req, err = readRequest(server)
		if err != nil {
			return
		}
		cancelled <- req.CancelResendingMessage.MessageID
		sendResponse(t, server, &Response{CancelResendingMessageReply: &CancelResendingMessageReply{
			QueryID: req.CancelResendingMessage.QueryID,
		}})
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-started
		cancel()
	}()
	_, err := tc.StartResendingMessage(ctx, &[32]byte{}, []byte("q"), []byte("p"))
	require.ErrorIs(t, err, context.Canceled)

	select {
	case id := <-cancelled:
		require.NotNil(t, id)
	case <-time.After(5 * time.Second):
		t.Fatal("the daemon was not told to stop")
	}
}

func TestStartResendingMessageRejectsNilDestination(t *testing.T) {
	tc, _ := dialFakeDaemon(t)
	_, err := tc.StartResendingMessage(context.Background(), nil, []byte("q"), []byte("p"))
	require.Error(t, err)
}

func TestCancelResendingMessageReturnsTheDaemonError(t *testing.T) {
	tc, server := dialFakeDaemon(t)
	serveOneReply(t, server, func(req *Request) *Response {
		return &Response{CancelResendingMessageReply: &CancelResendingMessageReply{
			QueryID: req.CancelResendingMessage.QueryID, ErrorCode: ThinClientErrorInvalidRequest,
		}}
	})
	require.Error(t, tc.CancelResendingMessage(&[32]byte{0x09}))
	require.Error(t, tc.CancelResendingMessage(nil))
}
