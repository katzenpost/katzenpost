// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"

	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

type CreateWriteChannel struct {
	BoxOwnerCap     *bacap.BoxOwnerCap     `cbor:"box_owner_cap,omitempty"`     // For resuming existing channel
	MessageBoxIndex *bacap.MessageBoxIndex `cbor:"message_box_index,omitempty"` // Starting/resume point
}

type CreateReadChannel struct {
	ReadCap         *bacap.UniversalReadCap `cbor:"read_cap"`
	MessageBoxIndex *bacap.MessageBoxIndex  `cbor:"message_box_index,omitempty"` // Starting/resume point
}

type WriteChannel struct {
	ChannelID [ChannelIDLength]byte `cbor:"channel_id"`
	Payload   []byte                `cbor:"payload"`
}

type ReadChannel struct {
	ChannelID [ChannelIDLength]byte  `cbor:"channel_id"`
	ID        *[MessageIDLength]byte `cbor:"id,omitempty"` // Optional for correlation
}

type CopyChannel struct {
	ChannelID [ChannelIDLength]byte  `cbor:"channel_id"`
	ID        *[MessageIDLength]byte `cbor:"id"`
}

type SendMessage struct {
	// ID is the unique identifier with respect to the Payload.
	// This is only used by the ARQ.
	ID *[MessageIDLength]byte `cbor:"id"`

	// WithSURB indicates if the message should be sent with a SURB
	// in the Sphinx payload.
	WithSURB bool `cbor:"with_surb"`

	// SURBID must be a unique identity for each request.
	// This field should be nil if WithSURB is false.
	SURBID *[sConstants.SURBIDLength]byte `cbor:"surbid"`

	// DestinationIdHash is 32 byte hash of the destination Provider's
	// identity public key.
	DestinationIdHash *[hash.HashSize]byte `cbor:"destination_id_hash"`

	// RecipientQueueID is the queue identity which will receive the message.
	RecipientQueueID []byte `cbor:"recipient_queue_id"`

	// Payload is the actual Sphinx packet.
	Payload []byte `cbor:"payload"`
}

type SendARQMessage struct {
	// ID is the unique identifier with respect to the Payload.
	// This is only used by the ARQ.
	ID *[MessageIDLength]byte `cbor:"id"`

	// WithSURB indicates if the message should be sent with a SURB
	// in the Sphinx payload.
	WithSURB bool `cbor:"with_surb"`

	// SURBID must be a unique identity for each request.
	// This field should be nil if WithSURB is false.
	SURBID *[sConstants.SURBIDLength]byte `cbor:"surbid"`

	// DestinationIdHash is 32 byte hash of the destination Provider's
	// identity public key.
	DestinationIdHash *[hash.HashSize]byte `cbor:"destination_id_hash"`

	// RecipientQueueID is the queue identity which will receive the message.
	RecipientQueueID []byte `cbor:"recipient_queue_id"`

	// Payload is the actual Sphinx packet.
	Payload []byte `cbor:"payload"`
}

type SendLoopDecoy struct {
}

type SendDropDecoy struct {
}

type ThinClose struct {
}

type Response struct {
	ShutdownEvent *ShutdownEvent `cbor:"shudown_event"`

	ConnectionStatusEvent *ConnectionStatusEvent `cbor:"connection_status_event"`

	NewPKIDocumentEvent *NewPKIDocumentEvent `cbor:"new_pki_document_event"`

	MessageSentEvent *MessageSentEvent `cbor:"message_sent_event"`

	MessageReplyEvent *MessageReplyEvent `cbor:"message_reply_event"`

	MessageIDGarbageCollected *MessageIDGarbageCollected `cbor:"message_id_garbage_collected"`

	CreateWriteChannelReply *CreateWriteChannelReply `cbor:"create_write_channel_reply"`

	CreateReadChannelReply *CreateReadChannelReply `cbor:"create_read_channel_reply"`

	WriteChannelReply *WriteChannelReply `cbor:"write_channel_reply"`

	ReadChannelReply *ReadChannelReply `cbor:"read_channel_reply"`

	CopyChannelReply *CopyChannelReply `cbor:"copy_channel_reply"`
}

type Request struct {
	// CreateWriteChannel is used to create a new Pigeonhole write channel.
	CreateWriteChannel *CreateWriteChannel `cbor:"create_write_channel"`

	// CreateReadChannel is used to create a new Pigeonhole read channel.
	CreateReadChannel *CreateReadChannel `cbor:"create_read_channel"`

	// WriteChannel is used to write to a Pigeonhole channel.
	WriteChannel *WriteChannel `cbor:"write_channel"`

	// ReadChannel is used to read from a Pigeonhole channel.
	ReadChannel *ReadChannel `cbor:"read_channel"`

	// CopyChannel is used to copy a Pigeonhole channel.
	CopyChannel *CopyChannel `cbor:"copy_channel"`

	// SendMessage is used to send a message through the mix network.
	SendMessage *SendMessage `cbor:"send_message"`

	// SendARQMessage is used to send a message through the mix network
	// using the naive ARQ error correction scheme.
	SendARQMessage *SendARQMessage `cbor:"send_arq_message"`

	// SendLoopDecoy is used to send a loop decoy message.
	SendLoopDecoy *SendLoopDecoy `cbor:"send_loop_decoy"`

	// SendDropDecoy is used to send a drop decoy message.
	SendDropDecoy *SendDropDecoy `cbor:"send_drop_decoy"`

	// ThinClose is used to indicate that the thin client is disconnecting
	// from the daemon.
	ThinClose *ThinClose `cbor:"thin_close"`
}
