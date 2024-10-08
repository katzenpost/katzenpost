// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only
package client2

import (
	"github.com/katzenpost/katzenpost/client2/thin"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

func IntoThinResponse(r *Response) *thin.Response {
	return &thin.Response{
		ConnectionStatusEvent:     r.ConnectionStatusEvent,
		NewPKIDocumentEvent:       r.NewPKIDocumentEvent,
		MessageSentEvent:          r.MessageSentEvent,
		MessageReplyEvent:         r.MessageReplyEvent,
		MessageIDGarbageCollected: r.MessageIDGarbageCollected,
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
}

func FromThinRequest(r *thin.Request, appid *[AppIDLength]byte) *Request {
	return &Request{
		AppID:             appid,
		ID:                r.ID,
		WithSURB:          r.WithSURB,
		SURBID:            r.SURBID,
		DestinationIdHash: r.DestinationIdHash,
		RecipientQueueID:  r.RecipientQueueID,
		Payload:           r.Payload,
		IsSendOp:          r.IsSendOp,
		IsARQSendOp:       r.IsARQSendOp,
		IsLoopDecoy:       r.IsLoopDecoy,
		IsDropDecoy:       r.IsDropDecoy,
		IsThinClose:       r.IsThinClose,
	}
}

type Request struct {
	// ID is the unique identifier with respect to the Payload.
	// This is only used by the ARQ.
	ID *[MessageIDLength]byte

	// WithSURB indicates if the message should be sent with a SURB
	// in the Sphinx payload.
	WithSURB bool

	// SURBID must be a unique identity for each request.
	// This field should be nil if WithSURB is false.
	SURBID *[sConstants.SURBIDLength]byte

	// AppID must be a unique identity for the client application
	// that is sending this Request.
	AppID *[AppIDLength]byte

	// DestinationIdHash is 32 byte hash of the destination Provider's
	// identity public key.
	DestinationIdHash *[32]byte

	// RecipientQueueID is the queue identity which will receive the message.
	RecipientQueueID []byte

	// Payload is the actual Sphinx packet.
	Payload []byte

	// IsSendOp is set to true if the intent is to send a message through
	// the mix network.
	IsSendOp bool

	// IsARQSendOp is set to true if the intent is to send a message through
	// the mix network using the naive ARQ error correction scheme.
	IsARQSendOp bool

	// IsLoopDecoy is set to true to indicate that this message shall
	// be a loop decoy message.
	IsLoopDecoy bool

	// IsDropDecoy is set to true to indicate that this message shall
	// be a drop decoy message.
	IsDropDecoy bool

	// IsThinClose is set to true to indicate that the thin client
	// is disconnecting from the daemon.
	IsThinClose bool
}
