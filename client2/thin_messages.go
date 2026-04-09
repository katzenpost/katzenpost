// SPDX-FileCopyrightText: (c) 2024, 2025  David Stainton.
// SPDX-License-Identifier: AGPL-3.0-only
package client2

import (
	"github.com/katzenpost/katzenpost/client2/thin"
)

func IntoThinResponse(r *Response) *thin.Response {
	return &thin.Response{
		SessionTokenReply:         r.SessionTokenReply,
		ShutdownEvent:             r.ShutdownEvent,
		ConnectionStatusEvent:     r.ConnectionStatusEvent,
		NewPKIDocumentEvent:       r.NewPKIDocumentEvent,
		MessageSentEvent:          r.MessageSentEvent,
		MessageReplyEvent:         r.MessageReplyEvent,
		MessageIDGarbageCollected: r.MessageIDGarbageCollected,

		// New Pigeonhole API:
		NewKeypairReply:                      r.NewKeypairReply,
		EncryptReadReply:                     r.EncryptReadReply,
		EncryptWriteReply:                    r.EncryptWriteReply,
		StartResendingEncryptedMessageReply:  r.StartResendingEncryptedMessageReply,
		CancelResendingEncryptedMessageReply: r.CancelResendingEncryptedMessageReply,
		StartResendingCopyCommandReply:       r.StartResendingCopyCommandReply,
		CancelResendingCopyCommandReply:      r.CancelResendingCopyCommandReply,
		NextMessageBoxIndexReply:             r.NextMessageBoxIndexReply,

		// Copy Channel API:
		CreateCourierEnvelopesFromPayloadReply:  r.CreateCourierEnvelopesFromPayloadReply,
		CreateCourierEnvelopesFromPayloadsReply: r.CreateCourierEnvelopesFromPayloadsReply,
		SetStreamBufferReply:                    r.SetStreamBufferReply,

	}
}

type Response struct {
	// AppID must be a unique identity for the client application
	// that is receiving this Response.
	AppID *[AppIDLength]byte

	SessionTokenReply *thin.SessionTokenReply

	ShutdownEvent *thin.ShutdownEvent

	ConnectionStatusEvent *thin.ConnectionStatusEvent

	NewPKIDocumentEvent *thin.NewPKIDocumentEvent

	MessageSentEvent *thin.MessageSentEvent

	MessageReplyEvent *thin.MessageReplyEvent

	MessageIDGarbageCollected *thin.MessageIDGarbageCollected

	// New Pigeonhole API:

	NewKeypairReply *thin.NewKeypairReply

	EncryptReadReply *thin.EncryptReadReply

	EncryptWriteReply *thin.EncryptWriteReply

	StartResendingEncryptedMessageReply *thin.StartResendingEncryptedMessageReply

	CancelResendingEncryptedMessageReply *thin.CancelResendingEncryptedMessageReply

	StartResendingCopyCommandReply *thin.StartResendingCopyCommandReply

	CancelResendingCopyCommandReply *thin.CancelResendingCopyCommandReply

	NextMessageBoxIndexReply *thin.NextMessageBoxIndexReply

	// Copy Channel API:

	CreateCourierEnvelopesFromPayloadReply *thin.CreateCourierEnvelopesFromPayloadReply

	CreateCourierEnvelopesFromPayloadsReply *thin.CreateCourierEnvelopesFromPayloadsReply

	SetStreamBufferReply *thin.SetStreamBufferReply

}

func FromThinRequest(r *thin.Request, appid *[AppIDLength]byte) *Request {
	return &Request{
		AppID: appid,

		// New Pigeonhole API:
		NewKeypair:                      r.NewKeypair,
		EncryptRead:                     r.EncryptRead,
		EncryptWrite:                    r.EncryptWrite,
		StartResendingEncryptedMessage:  r.StartResendingEncryptedMessage,
		CancelResendingEncryptedMessage: r.CancelResendingEncryptedMessage,
		StartResendingCopyCommand:       r.StartResendingCopyCommand,
		CancelResendingCopyCommand:      r.CancelResendingCopyCommand,
		NextMessageBoxIndex:             r.NextMessageBoxIndex,

		// Copy Channel API:
		CreateCourierEnvelopesFromPayload:  r.CreateCourierEnvelopesFromPayload,
		CreateCourierEnvelopesFromPayloads: r.CreateCourierEnvelopesFromPayloads,
		SetStreamBuffer:                    r.SetStreamBuffer,

		SessionToken: r.SessionToken,
		SendMessage:  r.SendMessage,
		ThinClose:    r.ThinClose,
	}
}

type SendLoopDecoy struct {
}

type SendDropDecoy struct {
}

type Request struct {
	// AppID must be a unique identity for the client application
	// that is sending this Request.
	AppID *[AppIDLength]byte

	// New Pigeonhole API:

	NewKeypair *thin.NewKeypair

	EncryptRead *thin.EncryptRead

	EncryptWrite *thin.EncryptWrite

	StartResendingEncryptedMessage *thin.StartResendingEncryptedMessage

	CancelResendingEncryptedMessage *thin.CancelResendingEncryptedMessage

	StartResendingCopyCommand *thin.StartResendingCopyCommand

	CancelResendingCopyCommand *thin.CancelResendingCopyCommand

	NextMessageBoxIndex *thin.NextMessageBoxIndex

	// Copy Channel API:

	CreateCourierEnvelopesFromPayload *thin.CreateCourierEnvelopesFromPayload

	CreateCourierEnvelopesFromPayloads *thin.CreateCourierEnvelopesFromPayloads

	SetStreamBuffer *thin.SetStreamBuffer

	SessionToken *thin.SessionToken

	// Core functionality

	ThinClose *thin.ThinClose

	// Decoys

	SendLoopDecoy *SendLoopDecoy

	SendDropDecoy *SendDropDecoy

	// Legacy API

	SendMessage *thin.SendMessage
}
