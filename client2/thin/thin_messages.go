// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package thin provides message types for the thin client protocol.
// This file defines the request and response message structures used for
// communication between thin clients and the client daemon via CBOR encoding.
//
// The protocol supports various operations including:
//   - Basic message sending with optional SURBs (Single Use Reply Blocks)
//   - Reliable message delivery using ARQ (Automatic Repeat Request)
//   - Pigeonhole channel operations for persistent communication
//   - Decoy traffic generation for traffic analysis resistance
//
// All messages are serialized using CBOR (Concise Binary Object Representation)
// for efficient and reliable communication between client and daemon.
package thin

import (
	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"

	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

// CreateWriteChannel requests the creation of a new pigeonhole write channel
// or the resumption of an existing one. Write channels allow sending messages
// to a persistent communication channel that can be read by holders of the
// corresponding read capability.
type CreateWriteChannel struct {
	// WriteCap is the write capability for resuming an existing channel.
	// If nil, a new channel will be created. If provided, the channel will
	// be resumed from the specified MessageBoxIndex position.
	WriteCap *bacap.WriteCap `cbor:"write_cap,omitempty"`

	// MessageBoxIndex specifies the starting or resume point for the channel.
	// This field is required when resuming an existing channel (WriteCap != nil)
	// and optional when creating a new channel (defaults to a random starting point).
	MessageBoxIndex *bacap.MessageBoxIndex `cbor:"message_box_index,omitempty"`
}

// CreateReadChannel requests the creation of a new pigeonhole read channel
// from an existing read capability. Read channels allow receiving messages
// from a communication channel created by the holder of the write capability.
type CreateReadChannel struct {
	// ReadCap is the read capability that grants access to the channel.
	// This capability is typically shared by the channel creator and allows
	// reading messages from the specified channel.
	ReadCap *bacap.ReadCap `cbor:"read_cap"`

	// MessageBoxIndex specifies the starting point for reading from the channel.
	// If nil, reading will start from the channel's current position.
	// If provided, reading will start from the specified index.
	MessageBoxIndex *bacap.MessageBoxIndex `cbor:"message_box_index,omitempty"`
}

// WriteChannel requests writing a message to an existing pigeonhole channel.
// The daemon will prepare the message for transmission and return the
// serialized payload that should be sent via SendMessage.
type WriteChannel struct {
	// ChannelID identifies the target channel for the write operation.
	// This ID was returned when the channel was created.
	ChannelID uint16 `cbor:"channel_id"`

	// Payload contains the message data to write to the channel.
	// The payload size must not exceed the channel's configured limits.
	Payload []byte `cbor:"payload"`
}

// ReadChannel requests reading the next message from a pigeonhole channel.
// The daemon will prepare a query for the next available message and return
// the serialized payload that should be sent via SendMessage.
type ReadChannel struct {
	// ChannelID identifies the source channel for the read operation.
	// This ID was returned when the channel was created.
	ChannelID uint16 `cbor:"channel_id"`

	// MessageID is used for correlating the read request with its response.
	// This allows the client to match responses to specific read operations.
	MessageID *[MessageIDLength]byte `cbor:"id,omitempty"`
}

// CopyChannel requests copying data from a pigeonhole channel to storage replicas
// via the courier system. This operation ensures message persistence and availability
// across multiple storage nodes in the network.
type CopyChannel struct {
	// ChannelID identifies the source channel for the copy operation.
	// This ID was returned when the channel was created.
	ChannelID uint16 `cbor:"channel_id"`

	// MessageID is used for correlating the copy request with its response.
	// This allows the client to track the completion of copy operations.
	MessageID *[MessageIDLength]byte `cbor:"id"`
}

// SendMessage requests sending a message through the mixnet using the Sphinx
// packet format. This is the basic message sending operation that supports
// both one-way messages and messages with reply capabilities via SURBs.
type SendMessage struct {
	// ID is a unique identifier for this message, used primarily for ARQ
	// (Automatic Repeat Request) operations and message tracking.
	// This field may be nil for simple one-way messages.
	ID *[MessageIDLength]byte `cbor:"id"`

	// WithSURB indicates whether the message should include a Single Use Reply Block
	// (SURB) that allows the recipient to send a reply back through the mixnet.
	// When true, the SURBID field must also be provided.
	WithSURB bool `cbor:"with_surb"`

	// SURBID is a unique identifier for the SURB included with this message.
	// This ID is used to correlate replies with the original message.
	// This field must be nil if WithSURB is false.
	SURBID *[sConstants.SURBIDLength]byte `cbor:"surbid"`

	// DestinationIdHash is the 32-byte hash of the destination provider's
	// identity public key. This identifies which mixnet provider should
	// receive and process the message.
	DestinationIdHash *[hash.HashSize]byte `cbor:"destination_id_hash"`

	// RecipientQueueID identifies the specific queue or service at the
	// destination provider that should receive this message. This allows
	// providers to route messages to different services or applications.
	RecipientQueueID []byte `cbor:"recipient_queue_id"`

	// Payload contains the actual Sphinx packet data to be transmitted
	// through the mixnet. This includes the encrypted message content
	// and routing information.
	Payload []byte `cbor:"payload"`
}

// SendARQMessage requests sending a message with Automatic Repeat Request (ARQ)
// reliability guarantees. ARQ provides reliable delivery by automatically
// retransmitting messages until acknowledgment is received or maximum retries
// are exceeded.
type SendARQMessage struct {
	// ID is a unique identifier for this ARQ message, used for tracking
	// retransmissions and correlating acknowledgments. This field is required
	// for ARQ operations.
	ID *[MessageIDLength]byte `cbor:"id"`

	// WithSURB indicates whether the message should include a Single Use Reply Block
	// (SURB) for receiving replies. ARQ messages typically use SURBs for
	// acknowledgments and response delivery.
	WithSURB bool `cbor:"with_surb"`

	// SURBID is a unique identifier for the SURB included with this message.
	// This ID is used to correlate acknowledgments and replies with the
	// original ARQ message. This field must be nil if WithSURB is false.
	SURBID *[sConstants.SURBIDLength]byte `cbor:"surbid"`

	// DestinationIdHash is the 32-byte hash of the destination provider's
	// identity public key. This identifies which mixnet provider should
	// receive and process the ARQ message.
	DestinationIdHash *[hash.HashSize]byte `cbor:"destination_id_hash"`

	// RecipientQueueID identifies the specific queue or service at the
	// destination provider that should receive this ARQ message.
	RecipientQueueID []byte `cbor:"recipient_queue_id"`

	// Payload contains the actual Sphinx packet data for the ARQ message.
	// This includes the encrypted message content and routing information.
	Payload []byte `cbor:"payload"`
}

// SendLoopDecoy requests sending a loop decoy message for traffic analysis resistance.
// Loop decoys are messages that are routed through the mixnet but return to the
// sender, helping to obscure real traffic patterns without requiring a destination.
type SendLoopDecoy struct {
	// This struct is intentionally empty as loop decoys require no additional parameters.
	// The daemon will generate appropriate decoy traffic automatically.
}

// SendDropDecoy requests sending a drop decoy message for traffic analysis resistance.
// Drop decoys are messages that are routed partway through the mixnet and then
// discarded, helping to obscure real traffic patterns and timing.
type SendDropDecoy struct {
	// This struct is intentionally empty as drop decoys require no additional parameters.
	// The daemon will generate appropriate decoy traffic automatically.
}

// ThinClose indicates that the thin client is disconnecting from the daemon.
// This allows for graceful shutdown and cleanup of resources on both sides
// of the connection.
type ThinClose struct {
	// This struct is intentionally empty as no additional parameters are needed
	// for the close operation.
}

// Response represents a message sent from the daemon to the thin client.
// Each response contains exactly one event or reply, with all other fields
// being nil. The response type is determined by which field is non-nil.
//
// Responses are sent asynchronously and may arrive in any order relative
// to the requests that triggered them. Applications should use the event
// system or message correlation to handle responses appropriately.
type Response struct {
	// ShutdownEvent indicates that the daemon is shutting down
	ShutdownEvent *ShutdownEvent `cbor:"shudown_event"`

	// ConnectionStatusEvent reports changes in mixnet connectivity
	ConnectionStatusEvent *ConnectionStatusEvent `cbor:"connection_status_event"`

	// NewPKIDocumentEvent delivers updated PKI information
	NewPKIDocumentEvent *NewPKIDocumentEvent `cbor:"new_pki_document_event"`

	// MessageSentEvent confirms that a message has been transmitted
	MessageSentEvent *MessageSentEvent `cbor:"message_sent_event"`

	// MessageReplyEvent delivers a received reply message
	MessageReplyEvent *MessageReplyEvent `cbor:"message_reply_event"`

	// MessageIDGarbageCollected notifies that a message ID has been cleaned up
	MessageIDGarbageCollected *MessageIDGarbageCollected `cbor:"message_id_garbage_collected"`

	// CreateWriteChannelReply responds to write channel creation requests
	CreateWriteChannelReply *CreateWriteChannelReply `cbor:"create_write_channel_reply"`

	// CreateReadChannelReply responds to read channel creation requests
	CreateReadChannelReply *CreateReadChannelReply `cbor:"create_read_channel_reply"`

	// WriteChannelReply responds to channel write requests
	WriteChannelReply *WriteChannelReply `cbor:"write_channel_reply"`

	// ReadChannelReply responds to channel read requests
	ReadChannelReply *ReadChannelReply `cbor:"read_channel_reply"`

	// CopyChannelReply responds to channel copy requests
	CopyChannelReply *CopyChannelReply `cbor:"copy_channel_reply"`
}

// Request represents a message sent from the thin client to the daemon.
// Each request contains exactly one operation, with all other fields being nil.
// The request type is determined by which field is non-nil.
//
// Requests are processed by the daemon and may result in one or more response
// messages being sent back to the client asynchronously.
type Request struct {
	// CreateWriteChannel requests creation of a new pigeonhole write channel
	// or resumption of an existing one.
	CreateWriteChannel *CreateWriteChannel `cbor:"create_write_channel"`

	// CreateReadChannel requests creation of a new pigeonhole read channel
	// from an existing read capability.
	CreateReadChannel *CreateReadChannel `cbor:"create_read_channel"`

	// WriteChannel requests writing a message to an existing pigeonhole channel.
	WriteChannel *WriteChannel `cbor:"write_channel"`

	// ReadChannel requests reading the next message from a pigeonhole channel.
	ReadChannel *ReadChannel `cbor:"read_channel"`

	// CopyChannel requests copying channel data to storage replicas.
	CopyChannel *CopyChannel `cbor:"copy_channel"`

	// SendMessage requests sending a message through the mixnet.
	SendMessage *SendMessage `cbor:"send_message"`

	// SendARQMessage requests sending a message with automatic repeat request
	// reliability guarantees.
	SendARQMessage *SendARQMessage `cbor:"send_arq_message"`

	// SendLoopDecoy requests sending a loop decoy message for traffic analysis resistance.
	SendLoopDecoy *SendLoopDecoy `cbor:"send_loop_decoy"`

	// SendDropDecoy requests sending a drop decoy message for traffic analysis resistance.
	SendDropDecoy *SendDropDecoy `cbor:"send_drop_decoy"`

	// ThinClose indicates that the thin client is disconnecting from the daemon.
	ThinClose *ThinClose `cbor:"thin_close"`
}
