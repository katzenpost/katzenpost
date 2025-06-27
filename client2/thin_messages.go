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
		CreateReadChannelV2Reply:  r.CreateReadChannelV2Reply,
		WriteChannelV2Reply:       r.WriteChannelV2Reply,
		ReadChannelV2Reply:        r.ReadChannelV2Reply,
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

	CreateReadChannelV2Reply *thin.CreateReadChannelV2Reply

	WriteChannelV2Reply *thin.WriteChannelV2Reply

	ReadChannelV2Reply *thin.ReadChannelV2Reply
}

func FromThinRequest(r *thin.Request, appid *[AppIDLength]byte) *Request {
	return &Request{
		AppID:               appid,
		CreateWriteChannel:  r.CreateWriteChannel,
		CreateReadChannelV2: r.CreateReadChannelV2,
		WriteChannelV2:      r.WriteChannelV2,
		ReadChannelV2:       r.ReadChannelV2,

		SendMessage:    r.SendMessage,
		SendARQMessage: r.SendARQMessage,
		SendLoopDecoy:  r.SendLoopDecoy,
		SendDropDecoy:  r.SendDropDecoy,
		ThinClose:      r.ThinClose,
	}
}

type Request struct {
	CreateWriteChannel *thin.CreateWriteChannel

	CreateReadChannelV2 *thin.CreateReadChannelV2

	WriteChannelV2 *thin.WriteChannelV2

	ReadChannelV2 *thin.ReadChannelV2

	SendMessage *thin.SendMessage

	SendARQMessage *thin.SendARQMessage

	SendLoopDecoy *thin.SendLoopDecoy

	SendDropDecoy *thin.SendDropDecoy

	ThinClose *thin.ThinClose

	// AppID must be a unique identity for the client application
	// that is sending this Request.
	AppID *[AppIDLength]byte
}
