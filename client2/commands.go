// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only
package client2

import (
	"time"

	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

type Response struct {
	// ID is the unique identifier with respect to the Request Payload.
	// This is only used by the ARQ.
	ID *[MessageIDLength]byte

	// SURBID must be a unique identity for each request.
	SURBID *[sConstants.SURBIDLength]byte `cbor:surbid`

	// AppID must be a unique identity for the client application
	// that is receiving this Response.
	AppID uint64 `cbor:id`

	// Payload contains the Response payload, a SURB reply.
	Payload []byte `cbor:payload`

	// IsMessageSent is used to indicate that this response
	// identifies a specific message was sent sucessfully.
	IsMessageSent bool

	// SentAt contains the time the message was sent.
	SentAt time.Time

	// ReplyETA is the expected round trip time to receive a response.
	ReplyETA time.Duration

	// Err is the error encountered when sending the message if any.
	Err error

	// IsStatus is set to true if Payload should be nil and IsConnected
	// regarded as the latest connection status.
	IsStatus bool `cbor:is_status`
	// IsConnected is the latest connection status if IsStatus is true.
	IsConnected bool `cbor:is_connected`

	// IsPKIDoc is to to true if the Payload contains a PKI document stripped
	// of signatures.
	IsPKIDoc bool `cbor:is_pki_doc`
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
	SURBID *[sConstants.SURBIDLength]byte `cbor:surbid`

	// AppID must be a unique identity for the client application
	// that is sending this Request.
	AppID uint64 `cbor:app_id`

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

	// IsEchoOp is set to true if the intent is to merely test that the unix
	// socket listener is working properly; the Response payload will be
	// contain the Request payload.
	IsEchoOp bool `cbor:is_echo_op`

	// IsLoopDecoy is set to true to indicate that this message shall
	// be a loop decoy message.
	IsLoopDecoy bool `cbor:is_loop_decoy`

	// IsDropDecoy is set to true to indicate that this message shall
	// be a drop decoy message.
	IsDropDecoy bool `cbor:is_drop_decoy`
}
