// SPDX-FileCopyrightText: (c) 2024, 2025  David Stainton.
// SPDX-License-Identifier: AGPL-3.0-only
package client2

import (
	"github.com/katzenpost/katzenpost/client2/thin"
)

func IntoThinResponse(r *Response) *thin.Response {
	return &thin.Response{
		ConnectionStatusEvent:     r.ConnectionStatusEvent,
		NewPKIDocumentEvent:       r.NewPKIDocumentEvent,
		MessageSentEvent:          r.MessageSentEvent,
		MessageReplyEvent:         r.MessageReplyEvent,
		MessageIDGarbageCollected: r.MessageIDGarbageCollected,
		CreateWriteChannelReply:   r.CreateWriteChannelReply,
		CreateReadChannelReply:    r.CreateReadChannelReply,
		WriteChannelReply:         r.WriteChannelReply,
		ReadChannelReply:          r.ReadChannelReply,
		ResumeWriteChannelReply:   r.ResumeWriteChannelReply,
		ResumeReadChannelReply:    r.ResumeReadChannelReply,
	}
}

type Response struct {
	// AppID must be a unique identity for the client application
	// that is receiving this Response.
	AppID *[AppIDLength]byte

	ShutdownEvent *thin.ShutdownEvent

	ConnectionStatusEvent *thin.ConnectionStatusEvent

	NewPKIDocumentEvent *thin.NewPKIDocumentEvent

	MessageSentEvent *thin.MessageSentEvent

	MessageReplyEvent *thin.MessageReplyEvent

	MessageIDGarbageCollected *thin.MessageIDGarbageCollected

	CreateWriteChannelReply *thin.CreateWriteChannelReply

	CreateReadChannelReply *thin.CreateReadChannelReply

	WriteChannelReply *thin.WriteChannelReply

	ReadChannelReply *thin.ReadChannelReply

	ResumeWriteChannelReply *thin.ResumeWriteChannelReply

	ResumeReadChannelReply *thin.ResumeReadChannelReply
}

func FromThinRequest(r *thin.Request, appid *[AppIDLength]byte) *Request {
	return &Request{
		AppID:              appid,
		CreateWriteChannel: r.CreateWriteChannel,
		CreateReadChannel:  r.CreateReadChannel,
		WriteChannel:       r.WriteChannel,
		ReadChannel:        r.ReadChannel,
		ResumeWriteChannel: r.ResumeWriteChannel,
		ResumeReadChannel:  r.ResumeReadChannel,
		CloseChannel:       r.CloseChannel,

		SendMessage:    r.SendMessage,
		SendARQMessage: r.SendARQMessage,
		SendLoopDecoy:  r.SendLoopDecoy,
		SendDropDecoy:  r.SendDropDecoy,
		ThinClose:      r.ThinClose,
	}
}

type Request struct {
	CreateWriteChannel *thin.CreateWriteChannel

	CreateReadChannel *thin.CreateReadChannel

	WriteChannel *thin.WriteChannel

	ReadChannel *thin.ReadChannel

	ResumeWriteChannel *thin.ResumeWriteChannel

	ResumeReadChannel *thin.ResumeReadChannel

	CloseChannel *thin.CloseChannel

	SendMessage *thin.SendMessage

	SendARQMessage *thin.SendARQMessage

	SendLoopDecoy *thin.SendLoopDecoy

	SendDropDecoy *thin.SendDropDecoy

	ThinClose *thin.ThinClose

	// AppID must be a unique identity for the client application
	// that is sending this Request.
	AppID *[AppIDLength]byte
}
