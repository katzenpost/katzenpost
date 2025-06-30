// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"fmt"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"

	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

// Thin client error codes provide standardized error reporting across the protocol.
// These codes are used in response messages to indicate the success or failure
// of operations, allowing applications to handle errors consistently.
const (
	// ThinClientSuccess indicates that the operation completed successfully
	// with no errors. This is the default success state.
	ThinClientSuccess uint8 = 0

	// ThinClientErrorConnectionLost indicates that the connection to the daemon
	// was lost during the operation. The client should attempt to reconnect.
	ThinClientErrorConnectionLost uint8 = 1

	// ThinClientErrorTimeout indicates that the operation timed out before
	// completion. This may occur during network operations or when waiting
	// for responses from the mixnet.
	ThinClientErrorTimeout uint8 = 2

	// ThinClientErrorInvalidRequest indicates that the request format was
	// invalid or contained malformed data that could not be processed.
	ThinClientErrorInvalidRequest uint8 = 3

	// ThinClientErrorInternalError indicates an internal error occurred within
	// the client daemon or thin client that prevented operation completion.
	ThinClientErrorInternalError uint8 = 4

	// ThinClientErrorMaxRetries indicates that the maximum number of retry
	// attempts was exceeded for a reliable operation (such as ARQ).
	ThinClientErrorMaxRetries uint8 = 5

	// ThinClientErrorInvalidChannel indicates that the specified channel ID
	// is invalid or malformed.
	ThinClientErrorInvalidChannel uint8 = 6

	// ThinClientErrorChannelNotFound indicates that the specified channel
	// does not exist or has been garbage collected.
	ThinClientErrorChannelNotFound uint8 = 7

	// ThinClientErrorPermissionDenied indicates that the operation was denied
	// due to insufficient permissions or capability restrictions.
	ThinClientErrorPermissionDenied uint8 = 8

	// ThinClientErrorInvalidPayload indicates that the message payload was
	// invalid, too large, or otherwise could not be processed.
	ThinClientErrorInvalidPayload uint8 = 9

	// ThinClientErrorServiceUnavailable indicates that the requested service
	// or functionality is currently unavailable.
	ThinClientErrorServiceUnavailable uint8 = 10

	// ThinClientErrorDuplicateCapability indicates that the provided capability
	// (read or write cap) has already been used and is considered a duplicate.
	ThinClientErrorDuplicateCapability uint8 = 11
)

// ThinClientErrorToString converts a thin client error code to a human-readable string.
// This function provides consistent error message formatting across the thin client
// protocol and is used for logging and error reporting.
//
// Parameters:
//   - errorCode: The error code to convert
//
// Returns:
//   - string: A human-readable description of the error
func ThinClientErrorToString(errorCode uint8) string {
	switch errorCode {
	case ThinClientSuccess:
		return "Success"
	case ThinClientErrorConnectionLost:
		return "Connection lost"
	case ThinClientErrorTimeout:
		return "Timeout"
	case ThinClientErrorInvalidRequest:
		return "Invalid request"
	case ThinClientErrorInternalError:
		return "Internal error"
	case ThinClientErrorMaxRetries:
		return "Maximum retries exceeded"
	case ThinClientErrorInvalidChannel:
		return "Invalid channel"
	case ThinClientErrorChannelNotFound:
		return "Channel not found"
	case ThinClientErrorPermissionDenied:
		return "Permission denied"
	case ThinClientErrorInvalidPayload:
		return "Invalid payload"
	case ThinClientErrorServiceUnavailable:
		return "Service unavailable"
	default:
		return fmt.Sprintf("Unknown thin client error code: %d", errorCode)
	}
}

type ChannelMap struct {
	ReadChannels  map[[ChannelIDLength]byte]*bacap.StatefulReader `cbor:"read_channels"`
	WriteChannels map[[ChannelIDLength]byte]*bacap.StatefulWriter `cbor:"write_channels"`
}

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

// String returns a string representation of the CreateWriteChannelReply.
func (e *CreateWriteChannelReply) String() string {
	if e.ErrorCode != ThinClientSuccess {
		return fmt.Sprintf("CreateWriteChannelReply: %d (error: %s)", e.ChannelID, ThinClientErrorToString(e.ErrorCode))
	}
	return fmt.Sprintf("CreateWriteChannelReply: %d", e.ChannelID)
}

// CreateReadChannel requests the creation of a new pigeonhole read channel
// from an existing read capability. Read channels allow receiving messages
// from a communication channel created by the holder of the write capability.
type CreateReadChannel struct {
	// ReadCap is the read capability that grants access to the channel.
	// This capability is typically shared by the channel creator and allows
	// reading messages from the specified channel.
	ReadCap *bacap.ReadCap `cbor:"read_cap"`

	// MessageBoxIndex specifies the starting read position for the channel.
	// If nil, reading will start from the beginning of the channel.
	MessageBoxIndex *bacap.MessageBoxIndex `cbor:"message_box_index,omitempty"`
}

// WriteChannel requests writing a message to an existing pigeonhole channel.
// The daemon will prepare the message for transmission and return the
// serialized payload that should be sent via SendChannelQuery.
type WriteChannel struct {
	// ChannelID identifies the target channel for the write operation.
	// This ID was returned when the channel was created.
	ChannelID uint16 `cbor:"channel_id"`

	// Payload contains the message data to write to the channel.
	// The payload size must not exceed the channel's configured limits.
	Payload []byte `cbor:"payload"`
}

// String returns a string representation of the WriteChannel request.
func (w *WriteChannel) String() string {
	return fmt.Sprintf("WriteChannel: channel=%d (%d bytes payload)", w.ChannelID, len(w.Payload))
}

// ReadChannel requests reading the next message from a pigeonhole channel.
// The daemon will prepare a query for the next available message and return
// the serialized payload that should be sent via SendChannelQuery.
type ReadChannel struct {
	// ChannelID identifies the source channel for the read operation.
	// This ID was returned when the channel was created.
	ChannelID uint16 `cbor:"channel_id"`

	// MessageID is used for correlating the read request with its response.
	// This allows the client to match responses to specific read operations.
	// This field is required.
	MessageID *[MessageIDLength]byte `cbor:"message_id"`

	// ReplyIndex is the index of the reply to return. It is optional and
	// a default of zero will be used if not specified.
	ReplyIndex *uint8 `cbor:"reply_index,omitempty"`
}

// String returns a string representation of the ReadChannel request.
func (r *ReadChannel) String() string {
	msgIDStr := "nil"
	if r.MessageID != nil {
		msgIDStr = fmt.Sprintf("%x", r.MessageID[:8]) // First 8 bytes for brevity
	}
	replyIndexStr := ""
	if r.ReplyIndex != nil {
		replyIndexStr = fmt.Sprintf(" replyIndex=%d", *r.ReplyIndex)
	}
	return fmt.Sprintf("ReadChannel: channel=%d msgID=%s%s", r.ChannelID, msgIDStr, replyIndexStr)
}

// CloseChannel requests closing a pigeonhole channel.
type CloseChannel struct {
	ChannelID uint16 `cbor:"channel_id"`
}

func (c *CloseChannel) String() string {
	return fmt.Sprintf("CloseChannel: channel=%d", c.ChannelID)
}

type SendMessage struct {
	// ID is the unique identifier with respect to the Payload.
	// This is only used by the ARQ.
	ID *[MessageIDLength]byte `cbor:"id"`

	// WithSURB indicates if the message should be sent with a SURB
	// in the Sphinx payload.
	WithSURB bool `cbor:"with_surb"`

	// ChannelID is optional and only used for sending channel messages.
	// For non-channel messages, this field should be nil.
	ChannelID *uint16 `cbor:"channel_id,omitempty"`

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
}

type Request struct {

	// NEW CHANNEL API

	// CreateWriteChannel is used to create a new Pigeonhole write channel.
	CreateWriteChannel *CreateWriteChannel `cbor:"create_write_channel"`

	// CreateReadChannel is used to create a new Pigeonhole read channel.
	CreateReadChannel *CreateReadChannel `cbor:"create_read_channel"`

	// WriteChannel is used to write to a Pigeonhole channel.
	WriteChannel *WriteChannel `cbor:"write_channel"`

	// ReadChannel is used to read from a Pigeonhole channel.
	ReadChannel *ReadChannel `cbor:"read_channel"`

	// CloseChannel is used to close a Pigeonhole channel.
	CloseChannel *CloseChannel `cbor:"close_channel"`

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
