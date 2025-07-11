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

	// ThinClientErrorCourierCacheCorruption indicates that the courier's cache
	// has detected corruption.
	ThinClientErrorCourierCacheCorruption uint8 = 12

	// ThinClientPropagationError indicates that the request could not be
	// propagated to replicas.
	ThinClientPropagationError uint8 = 13

	// ThinClientErrorInvalidWriteCapability indicates that the provided write
	// capability is invalid.
	ThinClientErrorInvalidWriteCapability uint8 = 14

	// ThinClientErrorInvalidReadCapability indicates that the provided read
	// capability is invalid.
	ThinClientErrorInvalidReadCapability uint8 = 15

	// ThinClientErrorInvalidResumeWriteChannelRequest indicates that the provided
	// ResumeWriteChannel request is invalid.
	ThinClientErrorInvalidResumeWriteChannelRequest uint8 = 16

	// ThinClientErrorInvalidResumeReadChannelRequest indicates that the provided
	// ResumeReadChannel request is invalid.
	ThinClientErrorInvalidResumeReadChannelRequest uint8 = 17

	// ThinClientImpossibleHashError indicates that the provided hash is impossible
	// to compute, such as when the hash of a write capability is provided but
	// the write capability itself is not provided.
	ThinClientImpossibleHashError uint8 = 18

	// ThinClientImpossibleNewWriteCapError indicates that the daemon was unable
	// to create a new write capability.
	ThinClientImpossibleNewWriteCapError uint8 = 19

	// ThinClientImpossibleNewStatefulWriterError indicates that the daemon was unable
	// to create a new stateful writer.
	ThinClientImpossibleNewStatefulWriterError uint8 = 20

	// ThinClientCapabilityAlreadyInUse indicates that the provided capability
	// is already in use.
	ThinClientCapabilityAlreadyInUse uint8 = 21
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
	case ThinClientErrorDuplicateCapability:
		return "Duplicate capability"
	case ThinClientErrorCourierCacheCorruption:
		return "Courier cache corruption"
	case ThinClientPropagationError:
		return "Propagation error"
	default:
		return fmt.Sprintf("Unknown thin client error code: %d", errorCode)
	}
}

type ChannelMap struct {
	ReadChannels  map[[ChannelIDLength]byte]*bacap.StatefulReader `cbor:"read_channels"`
	WriteChannels map[[ChannelIDLength]byte]*bacap.StatefulWriter `cbor:"write_channels"`
}

// CreateWriteChannel requests the creation of a new pigeonhole write channel.
// For channel resumption, please see the ResumeWriteChannel type below.
// The reply will contain the channel ID, read capability, write capability,
// and the current message index, all of which can be used by a clever client
// to resume the channel in the future even in the face of system reboots etc.
type CreateWriteChannel struct {

	// QueryID is used for correlating this thin client request with the
	// thin client reponse.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`
}

// CreateReadChannel requests the creation of a new pigeonhole read channel
// from an existing read capability. Read channels allow receiving messages
// from a communication channel created by the holder of the write capability.
type CreateReadChannel struct {

	// QueryID is used for correlating this thin client request with the
	// thin client reponse.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// ReadCap is the read capability that grants access to the channel.
	// This capability is typically shared by the channel creator and allows
	// reading messages from the specified channel.
	ReadCap *bacap.ReadCap `cbor:"read_cap"`
}

// WriteChannel requests writing a message to an existing pigeonhole channel.
// The daemon will prepare the message for transmission and return the
// serialized payload that should be sent via SendChannelQuery.
type WriteChannel struct {

	// QueryID is used for correlating the write request with its response.
	// This allows the client to match responses to specific write operations.
	// This field is required.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// ChannelID identifies the target channel for the write operation.
	// This ID was returned when the channel was created.
	ChannelID uint16 `cbor:"channel_id"`

	// Payload contains the message data to write to the channel.
	// The payload size must not exceed the channel's configured limits.
	Payload []byte `cbor:"payload"`
}

// ResumeWriteChannel requests resuming a write operation that was previously
// initiated but not yet completed.
type ResumeWriteChannel struct {

	// QueryID is used for correlating the write request with its response.
	// This allows the client to match responses to specific write operations.
	// This field is required.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// WriteCap is the write capability for resuming an existing channel.
	// If nil, a new channel will be created. If provided, the channel will
	// be resumed from the specified MessageBoxIndex position.
	WriteCap *bacap.WriteCap `cbor:"write_cap,omitempty"`

	// MessageBoxIndex specifies the starting or resume point for the channel.
	// This field is required when resuming an existing channel (WriteCap != nil)
	// and optional when creating a new channel (defaults to a random starting point).
	MessageBoxIndex *bacap.MessageBoxIndex `cbor:"message_box_index,omitempty"`
}

// ResumeWriteChannel requests resuming a write operation that was previously
// initiated but not yet completed.
type ResumeWriteChannelQuery struct {

	// QueryID is used for correlating the write request with its response.
	// This allows the client to match responses to specific write operations.
	// This field is required.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// WriteCap is the write capability for resuming an existing channel.
	// If nil, a new channel will be created. If provided, the channel will
	// be resumed from the specified MessageBoxIndex position.
	WriteCap *bacap.WriteCap `cbor:"write_cap,omitempty"`

	// MessageBoxIndex specifies the starting or resume point for the channel.
	// This field is required when resuming an existing channel (WriteCap != nil)
	// and optional when creating a new channel (defaults to a random starting point).
	MessageBoxIndex *bacap.MessageBoxIndex `cbor:"message_box_index,omitempty"`

	// EnvelopeDescriptor contains the serialized EnvelopeDescriptor that
	// contains the private key material needed to decrypt the envelope reply.
	EnvelopeDescriptor []byte `cbor:"envelope_descriptor"`

	// EnvelopeHash is the hash of the CourierEnvelope that was sent to the
	EnvelopeHash *[32]byte `cbor:"envelope_hash"`
}

// ReadChannel requests reading the next message from a pigeonhole channel.
// The daemon will prepare a query for the next available message and return
// the serialized payload that should be sent via SendChannelQuery.
type ReadChannel struct {
	// ChannelID identifies the source channel for the read operation.
	// This ID was returned when the channel was created.
	ChannelID uint16 `cbor:"channel_id"`

	// QueryID is used for correlating this thin client request with the
	// thin client reponse, the ReadChannelReply.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// MessageBoxIndex specifies the starting read position for the channel.
	// If nil, reading will start from the current index in the client daemon's
	// stateful reader. NOTE(David): This field is only needed because the
	// next field, ReplyIndex, requires us to specify *which* message should
	// be returned, since presumably the application will perform two read
	// queries if the first result is not available.
	MessageBoxIndex *bacap.MessageBoxIndex `cbor:"message_box_index,omitempty"`

	// ReplyIndex is the index of the reply to return. It is optional and
	// a default of zero will be used if not specified.
	ReplyIndex *uint8 `cbor:"reply_index"`
}

// ResumeReadChannel requests resuming a read operation that was previously
// initiated but not yet completed.
type ResumeReadChannel struct {
	// QueryID is used for correlating the read request with its response.
	// This allows the client to match responses to specific read operations.
	// This field is required.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// ReadCap is the read capability that grants access to the channel.
	// This capability is typically shared by the channel creator and allows
	// reading messages from the specified channel.
	ReadCap *bacap.ReadCap `cbor:"read_cap"`

	// NextMessageIndex indicates the message index to use after successfully
	// reading the current message.
	NextMessageIndex *bacap.MessageBoxIndex `cbor:"next_message_index"`

	// ReplyIndex is the index of the reply to return. It is optional and
	// a default of zero will be used if not specified.
	ReplyIndex *uint8 `cbor:"reply_index"`
}

// ResumeReadChannel requests resuming a read operation that was previously
// initiated but not yet completed.
type ResumeReadChannelQuery struct {
	// QueryID is used for correlating the read request with its response.
	// This allows the client to match responses to specific read operations.
	// This field is required.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// ReadCap is the read capability that grants access to the channel.
	// This capability is typically shared by the channel creator and allows
	// reading messages from the specified channel.
	ReadCap *bacap.ReadCap `cbor:"read_cap"`

	// NextMessageIndex indicates the message index to use after successfully
	// reading the current message.
	NextMessageIndex *bacap.MessageBoxIndex `cbor:"next_message_index"`

	// ReplyIndex is the index of the reply to return. It is optional and
	// a default of zero will be used if not specified.
	ReplyIndex *uint8 `cbor:"reply_index"`

	// EnvelopeDescriptor contains the serialized EnvelopeDescriptor that
	// contains the private key material needed to decrypt the envelope reply.
	EnvelopeDescriptor []byte `cbor:"envelope_descriptor"`

	// EnvelopeHash is the hash of the CourierEnvelope that was sent to the
	// mixnet and is used to resume the read operation.
	EnvelopeHash *[32]byte `cbor:"envelope_hash"`
}

// CloseChannel requests closing a pigeonhole channel.
type CloseChannel struct {
	ChannelID uint16 `cbor:"channel_id"`
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

type SendChannelQuery struct {
	// QueryID is used for correlating the request with its response.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// MessageID is the unique identifier for the request associated with the
	// query reply via the ChannelQueryReplyEvent.
	MessageID *[MessageIDLength]byte `cbor:"message_id"`

	// ChannelID is optional and only used for sending channel messages.
	// For non-channel messages, this field should be nil.
	ChannelID *uint16 `cbor:"channel_id,omitempty"`

	// DestinationIdHash is 32 byte hash of the destination Service's
	// identity public key.
	DestinationIdHash *[hash.HashSize]byte `cbor:"destination_id_hash"`

	// RecipientQueueID is the queue identity which will receive the message.
	RecipientQueueID []byte `cbor:"recipient_queue_id"`

	// Payload is the Pigeonole protocol ciphertext payload which will be encapsulated in the Sphinx payload.
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

	ResumeWriteChannelReply *ResumeWriteChannelReply `cbor:"resume_write_channel_reply"`

	ResumeWriteChannelQueryReply *ResumeWriteChannelQueryReply `cbor:"resume_write_channel_query_reply"`

	ResumeReadChannelReply *ResumeReadChannelReply `cbor:"resume_read_channel_reply"`

	ResumeReadChannelQueryReply *ResumeReadChannelQueryReply `cbor:"resume_read_channel_query_reply"`

	ChannelQuerySentEvent *ChannelQuerySentEvent `cbor:"channel_query_sent_event"`

	ChannelQueryReplyEvent *ChannelQueryReplyEvent `cbor:"channel_query_reply_event"`
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

	// ResumeWriteChannel is used to resume a write operation that was previously
	ResumeWriteChannel *ResumeWriteChannel `cbor:"resume_write_channel"`

	// ResumeWriteChannelQuery is used to resume a write operation that was previously
	ResumeWriteChannelQuery *ResumeWriteChannelQuery `cbor:"resume_write_channel_query"`

	// ResumeReadChannel is used to resume a read operation that was previously
	ResumeReadChannel *ResumeReadChannel `cbor:"resume_read_channel"`

	// ResumeReadChannelQuery is used to resume a read operation that was previously
	ResumeReadChannelQuery *ResumeReadChannelQuery `cbor:"resume_read_channel_query"`

	// CloseChannel is used to close a Pigeonhole channel.
	CloseChannel *CloseChannel `cbor:"close_channel"`

	// ThinClose is used to indicate that the thin client is disconnecting
	// from the daemon.
	ThinClose *ThinClose `cbor:"thin_close"`

	// SendChannelQuery is used to send a message through the mix network
	SendChannelQuery *SendChannelQuery `cbor:"send_channel_query"`

	// Legacy API

	// SendMessage is used to send a message through the mix network.
	SendMessage *SendMessage `cbor:"send_message"`

	// SendARQMessage is used to send a message through the mix network
	// using the naive ARQ error correction scheme.
	SendARQMessage *SendARQMessage `cbor:"send_arq_message"`

	// SendLoopDecoy is used to send a loop decoy message.
	SendLoopDecoy *SendLoopDecoy `cbor:"send_loop_decoy"`

	// SendDropDecoy is used to send a drop decoy message.
	SendDropDecoy *SendDropDecoy `cbor:"send_drop_decoy"`
}
