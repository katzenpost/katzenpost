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
	AppID *[AppIDLength]byte `cbor:app_id`

	ConnectionStatusEvent *thin.ConnectionStatusEvent `cbor:connection_status_event`

	NewPKIDocumentEvent *thin.NewPKIDocumentEvent `cbor:new_pki_document_event`

	MessageSentEvent *thin.MessageSentEvent `cbor:message_sent_event`

	MessageReplyEvent *thin.MessageReplyEvent `cbor:message_reply_event`

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
	}
}

type Request struct {
	// ID is the unique identifier with respect to the Payload.
	// This is only used by the ARQ.
	ID *[MessageIDLength]byte `cbor:id`

	// WithSURB indicates if the message should be sent with a SURB
	// in the Sphinx payload.
	WithSURB bool `cbor:with_surb`

	// SURBID must be a unique identity for each request.
	// This field should be nil if WithSURB is false.
	SURBID *[sConstants.SURBIDLength]byte `cbor:surbid`

	// AppID must be a unique identity for the client application
	// that is sending this Request.
	AppID *[AppIDLength]byte `cbor:app_id`

	// DestinationIdHash is 32 byte hash of the destination Provider's
	// identity public key.
	DestinationIdHash *[32]byte `cbor:destination_id_hash`

	// RecipientQueueID is the queue identity which will receive the message.
	RecipientQueueID []byte `cbor:recipient_queue_id`

	// Payload is the actual Sphinx packet.
	Payload []byte `cbor:payload`

	// IsSendOp is set to true if the intent is to send a message through
	// the mix network.
	IsSendOp bool `cbor:is_send_op`

	// IsARQSendOp is set to true if the intent is to send a message through
	// the mix network using the naive ARQ error correction scheme.
	IsARQSendOp bool `cbor:is_arq_send_op`

	// IsLoopDecoy is set to true to indicate that this message shall
	// be a loop decoy message.
	IsLoopDecoy bool `cbor:is_loop_decoy`

	// IsDropDecoy is set to true to indicate that this message shall
	// be a drop decoy message.
	IsDropDecoy bool `cbor:is_drop_decoy`
}
