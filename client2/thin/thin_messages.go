// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"fmt"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/core/sphinx/constants"
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

	// ThinClientErrorMKEMDecryptionFailed indicates that MKEM decryption failed.
	// This occurs when the MKEM envelope cannot be decrypted with any of the replica keys.
	ThinClientErrorMKEMDecryptionFailed uint8 = 22

	// ThinClientErrorBACAPDecryptionFailed indicates that BACAP decryption failed.
	// This occurs when the BACAP payload cannot be decrypted or signature verification fails.
	ThinClientErrorBACAPDecryptionFailed uint8 = 23

	// ThinClientErrorStartResendingCancelled indicates that a StartResendingEncryptedMessage
	// operation was cancelled via CancelResendingEncryptedMessage before completion.
	ThinClientErrorStartResendingCancelled uint8 = 24
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
	case ThinClientErrorMKEMDecryptionFailed:
		return "MKEM decryption failed"
	case ThinClientErrorBACAPDecryptionFailed:
		return "BACAP decryption failed"
	case ThinClientErrorStartResendingCancelled:
		return "Start resending cancelled"
	default:
		return fmt.Sprintf("Unknown thin client error code: %d", errorCode)
	}
}

// New Pigeonhole API:

// NewKeypair requests the creation of a new keypair for use with the Pigeonhole protocol.
// The reply type, is NewKeypairReply.
type NewKeypair struct {
	// QueryID is used for correlating this thin client request with the
	// thin client reponse.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`
	// Seed is the 32 byte seed used to derive the keypair.
	Seed []byte `cbor:"seed"`
}

// EncryptRead requests the encryption of a read operation for a given read capability.
type EncryptRead struct {
	// QueryID is used for correlating this thin client request with the
	// thin client reponse.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// ReadCap is the read capability that grants access to the channel.
	ReadCap *bacap.ReadCap `cbor:"read_cap"`

	// MessageBoxIndex specifies the starting read position for the channel.
	MessageBoxIndex *bacap.MessageBoxIndex `cbor:"message_box_index"`
}

// EncryptWrite requests the encryption of a write operation for a given write capability.
type EncryptWrite struct {
	// QueryID is used for correlating this thin client request with the
	// thin client reponse.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// Plaintext is the plaintext message to be encrypted.
	Plaintext []byte `cbor:"plaintext"`

	// WriteCap is the write capability that grants access to the channel.
	WriteCap *bacap.WriteCap `cbor:"write_cap"`

	// MessageBoxIndex specifies the starting write position for the channel.
	MessageBoxIndex *bacap.MessageBoxIndex `cbor:"message_box_index"`
}

// StartResendingEncryptedMessage requests the daemon to start resending an encrypted message.
type StartResendingEncryptedMessage struct {
	// QueryID is used for correlating this thin client request with the
	// thin client reponse.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// ReadCap is the read capability that grants access to the channel.
	ReadCap *bacap.ReadCap `cbor:"read_cap"`

	// WriteCap is the write capability that grants access to the channel.
	WriteCap *bacap.WriteCap `cbor:"write_cap"`

	// NextMessageIndex is the next message index that should be used when
	// encrypting the next read.
	NextMessageIndex []byte `cbor:"next_message_index"`

	// ReplyIndex is the index of the reply that was actually used when processing
	ReplyIndex *uint8 `cbor:"reply_index"`

	// EnvelopeDescriptor contains the serialized EnvelopeDescriptor that
	// contains the private key material needed to decrypt the envelope reply.
	EnvelopeDescriptor []byte `cbor:"envelope_descriptor"`

	// MessageCiphertext is the encrypted message ciphertext that should be sent
	MessageCiphertext []byte `cbor:"message_ciphertext"`

	// EnvelopeHash is the hash of the CourierEnvelope that was sent to the
	// mixnet and is used to resume the read operation.
	EnvelopeHash *[32]byte `cbor:"envelope_hash"`

	// ReplicaEpoch is the epoch in which the envelope was sent.
	ReplicaEpoch uint64 `cbor:"replica_epoch"`
}

// CancelResendingEncryptedMessage requests the daemon to cancel resending an encrypted message.
type CancelResendingEncryptedMessage struct {
	// QueryID is used for correlating this thin client request with the
	// thin client reponse.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// EnvelopeHash is the hash of the CourierEnvelope that was sent to the
	EnvelopeHash *[32]byte `cbor:"envelope_hash"`
}

// NextMessageBoxIndex requests the daemon to increment a MessageBoxIndex.
// This is used when sending multiple messages to different mailboxes using
// the same WriteCap. The reply type is NextMessageBoxIndexReply.
type NextMessageBoxIndex struct {
	// QueryID is used for correlating this thin client request with the
	// thin client reponse.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// MessageBoxIndex is the current index to increment.
	MessageBoxIndex *bacap.MessageBoxIndex `cbor:"message_box_index"`
}

// CreateCourierEnvelopesFromPayload creates multiple CourierEnvelopes from a payload of any size.
// The payload is automatically chunked and each chunk is wrapped in a CourierEnvelope.
// Each returned chunk is a serialized CopyStreamElement ready to be written to a box.
//
// Multiple calls can be made with the same StreamID to build up a stream incrementally.
// The first call creates a new encoder (first element gets IsStart=true).
// The final call should have IsLast=true (last element gets IsFinal=true).
type CreateCourierEnvelopesFromPayload struct {
	// QueryID is used for correlating this thin client request with the
	// thin client response.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// StreamID identifies the encoder instance for multi-call streams.
	// All calls for the same stream must use the same StreamID.
	// The encoder is created on first use and removed after IsLast=true.
	StreamID *[StreamIDLength]byte `cbor:"stream_id"`

	// Payload is the data to be written (any size).
	Payload []byte `cbor:"payload"`

	// DestWriteCap is the write capability for the destination channel.
	DestWriteCap *bacap.WriteCap `cbor:"dest_write_cap"`

	// DestStartIndex is the starting index in the destination channel.
	DestStartIndex *bacap.MessageBoxIndex `cbor:"dest_start_index"`

	// IsLast indicates whether this is the last payload in the sequence.
	// When true, the final CopyStreamElement will have IsFinal=true and
	// the encoder instance will be removed.
	IsLast bool `cbor:"is_last"`
}

// Common API:

// SendMessage is used to send a message through the mix network
// it is part of the legacy API and should not be used for newer
// works using the Pigeonhole protocol.
type SendMessage struct {
	// ID is the unique identifier with respect to the Payload.
	// This is only used by the ARQ.
	ID *[MessageIDLength]byte `cbor:"id"`

	// WithSURB indicates if the message should be sent with a SURB
	// in the Sphinx payload.
	WithSURB bool `cbor:"with_surb"`

	// SURBID must be a unique identity for each request.
	// This field should be nil if WithSURB is false.
	SURBID *[constants.SURBIDLength]byte `cbor:"surbid"`

	// DestinationIdHash is 32 byte hash of the destination Provider's
	// identity public key.
	DestinationIdHash *[hash.HashSize]byte `cbor:"destination_id_hash"`

	// RecipientQueueID is the queue identity which will receive the message.
	RecipientQueueID []byte `cbor:"recipient_queue_id"`

	// Payload is the actual Sphinx packet.
	Payload []byte `cbor:"payload"`
}

// ThinClose is used to indicate that the thin client is disconnecting
// from the daemon.
type ThinClose struct {
}

// Response is the client daemon's response message to the thin client.
type Response struct {

	// ShutdownEvent is sent when the client daemon is shutting down.
	ShutdownEvent *ShutdownEvent `cbor:"shudown_event"`

	// ConnectionStatusEvent is sent when the client daemon's connection status changes.
	ConnectionStatusEvent *ConnectionStatusEvent `cbor:"connection_status_event"`

	// NewPKIDocumentEvent is sent when the client daemon receives a new PKI document.
	NewPKIDocumentEvent *NewPKIDocumentEvent `cbor:"new_pki_document_event"`

	// MessageSentEvent is sent when the client daemon successfully sends a message.
	MessageSentEvent *MessageSentEvent `cbor:"message_sent_event"`

	// MessageReplyEvent is sent when the client daemon receives a reply to a message.
	MessageReplyEvent *MessageReplyEvent `cbor:"message_reply_event"`

	// MessageIDGarbageCollected is sent when the client daemon garbage collects a message ID.
	MessageIDGarbageCollected *MessageIDGarbageCollected `cbor:"message_id_garbage_collected"`

	// New Pigeonhole API:

	// NewKeypairReply is sent when the client daemon successfully creates a new keypair.
	NewKeypairReply *NewKeypairReply `cbor:"new_keypair_reply"`

	// EncryptReadReply is sent when the client daemon successfully encrypts a read operation.
	EncryptReadReply *EncryptReadReply `cbor:"encrypt_read_reply"`

	// EncryptWriteReply is sent when the client daemon successfully encrypts a write operation.
	EncryptWriteReply *EncryptWriteReply `cbor:"encrypt_write_reply"`

	// StartResendingEncryptedMessageReply is sent when the client daemon successfully starts resending an encrypted message.
	StartResendingEncryptedMessageReply *StartResendingEncryptedMessageReply `cbor:"start_resending_encrypted_message_reply"`

	// CancelResendingEncryptedMessageReply is sent when the client daemon successfully cancels resending an encrypted message.
	CancelResendingEncryptedMessageReply *CancelResendingEncryptedMessageReply `cbor:"cancel_resending_encrypted_message_reply"`

	// NextMessageBoxIndexReply is sent when the client daemon successfully increments a MessageBoxIndex.
	NextMessageBoxIndexReply *NextMessageBoxIndexReply `cbor:"next_message_box_index_reply"`

	// Old Pigeonhole API:

	// CreateWriteChannelReply is sent when the client daemon successfully creates a write channel.
	CreateWriteChannelReply *CreateWriteChannelReply `cbor:"create_write_channel_reply"`

	// CreateReadChannelReply is sent when the client daemon successfully creates a read channel.
	CreateReadChannelReply *CreateReadChannelReply `cbor:"create_read_channel_reply"`

	// WriteChannelReply is sent when the client daemon successfully writes a message to a channel.
	WriteChannelReply *WriteChannelReply `cbor:"write_channel_reply"`

	// ReadChannelReply is sent when the client daemon successfully reads a message from a channel.
	ReadChannelReply *ReadChannelReply `cbor:"read_channel_reply"`

	// ResumeWriteChannelReply is sent when the client daemon successfully resumes a write channel.
	ResumeWriteChannelReply *ResumeWriteChannelReply `cbor:"resume_write_channel_reply"`

	// ResumeWriteChannelQueryReply is sent when the client daemon successfully resumes a write channel.
	ResumeWriteChannelQueryReply *ResumeWriteChannelQueryReply `cbor:"resume_write_channel_query_reply"`

	// ResumeReadChannelReply is sent when the client daemon successfully resumes a read channel.
	ResumeReadChannelReply *ResumeReadChannelReply `cbor:"resume_read_channel_reply"`

	// ResumeReadChannelQueryReply is sent when the client daemon successfully resumes a read channel.
	ResumeReadChannelQueryReply *ResumeReadChannelQueryReply `cbor:"resume_read_channel_query_reply"`

	// ChannelQuerySentEvent is sent when the client daemon successfully sends a channel query.
	ChannelQuerySentEvent *ChannelQuerySentEvent `cbor:"channel_query_sent_event"`

	// ChannelQueryReplyEvent is sent when the client daemon receives a reply to a channel query.
	ChannelQueryReplyEvent *ChannelQueryReplyEvent `cbor:"channel_query_reply_event"`

	// Copy Channel API:

	// CreateCourierEnvelopesFromPayloadReply is sent when the client daemon successfully creates courier envelopes from a payload.
	CreateCourierEnvelopesFromPayloadReply *CreateCourierEnvelopesFromPayloadReply `cbor:"create_courier_envelopes_from_payload_reply"`
}

// Request is the thin client's request message to the client daemon.
// It can result in one or more Response messages being sent back to the thin client.
type Request struct {

	// ThinClose is used to indicate that the thin client is disconnecting
	// from the daemon.
	ThinClose *ThinClose `cbor:"thin_close"`

	// Legacy API

	// SendMessage is used to send a message through the mix network.
	// Note that this is part of the legacy API and should not be used for newer
	// works using the Pigeonhole protocol.
	SendMessage *SendMessage `cbor:"send_message"`

	// New Pigeonhole API:

	// NewKeypair is used to create a new keypair for use with the Pigeonhole protocol.
	NewKeypair *NewKeypair `cbor:"new_keypair"`

	// EncryptRead is used to encrypt a read operation for a given read capability.
	EncryptRead *EncryptRead `cbor:"encrypt_read"`

	// EncryptWrite is used to encrypt a write operation for a given write capability.
	EncryptWrite *EncryptWrite `cbor:"encrypt_write"`

	// StartResendingEncryptedMessage is used to start resending an encrypted message.
	StartResendingEncryptedMessage *StartResendingEncryptedMessage `cbor:"start_resending_encrypted_message"`

	// CancelResendingEncryptedMessage is used to cancel resending an encrypted message.
	CancelResendingEncryptedMessage *CancelResendingEncryptedMessage `cbor:"cancel_resending_encrypted_message"`

	// NextMessageBoxIndex is used to increment a MessageBoxIndex.
	NextMessageBoxIndex *NextMessageBoxIndex `cbor:"next_message_box_index"`

	// CreateCourierEnvelopesFromPayload is used to create multiple CourierEnvelopes from a payload of any size.
	CreateCourierEnvelopesFromPayload *CreateCourierEnvelopesFromPayload `cbor:"create_courier_envelopes_from_payload"`

	// OLD Pigeonhole API

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

	// SendChannelQuery is used to send a message through the mix network
	SendChannelQuery *SendChannelQuery `cbor:"send_channel_query"`
}
