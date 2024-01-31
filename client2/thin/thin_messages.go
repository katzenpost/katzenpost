// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

type Response struct {
	ConnectionStatusEvent *ConnectionStatusEvent `cbor:connection_status_event`

	NewPKIDocumentEvent *NewPKIDocumentEvent `cbor:new_pki_document_event`

	MessageSentEvent *MessageSentEvent `cbor:message_sent_event`

	MessageReplyEvent *MessageReplyEvent `cbor:message_reply_event`

	MessageIDGarbageCollected *MessageIDGarbageCollected
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
