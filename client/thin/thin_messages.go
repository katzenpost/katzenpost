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

	// ThinClientErrorInvalidTombstoneSig indicates that a replica claimed a box is
	// tombstoned but the signature verification failed. This means the tombstone is
	// forged or corrupted.
	ThinClientErrorInvalidTombstoneSig uint8 = 25

	// ThinClientErrorCopyCommandFailed indicates that the courier reported
	// CopyStatusFailed for a StartResendingCopyCommand operation. This is
	// a thin-client-namespace signal: the daemon sets it when it observes a
	// terminal CopyStatusFailed reply from the courier, independent of any
	// replica error code. The ancillary ReplicaErrorCode / FailedEnvelopeIndex
	// fields on the reply (if present) provide diagnostic detail, but the
	// sentinel mapping is driven entirely by this code.
	ThinClientErrorCopyCommandFailed uint8 = 26
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
	case ThinClientErrorInvalidWriteCapability:
		return "Invalid write capability"
	case ThinClientErrorInvalidReadCapability:
		return "Invalid read capability"
	case ThinClientErrorInvalidResumeWriteChannelRequest:
		return "Invalid resume write channel request"
	case ThinClientErrorInvalidResumeReadChannelRequest:
		return "Invalid resume read channel request"
	case ThinClientImpossibleHashError:
		return "Impossible hash error"
	case ThinClientImpossibleNewWriteCapError:
		return "Failed to create new write capability"
	case ThinClientImpossibleNewStatefulWriterError:
		return "Failed to create new stateful writer"
	case ThinClientCapabilityAlreadyInUse:
		return "Capability already in use"
	case ThinClientErrorMKEMDecryptionFailed:
		return "MKEM decryption failed"
	case ThinClientErrorBACAPDecryptionFailed:
		return "BACAP decryption failed"
	case ThinClientErrorStartResendingCancelled:
		return "Start resending cancelled"
	case ThinClientErrorInvalidTombstoneSig:
		return "Invalid tombstone signature"
	case ThinClientErrorCopyCommandFailed:
		return "Copy command failed"
	default:
		return fmt.Sprintf("Unknown thin client error code: %d", errorCode)
	}
}

// New Pigeonhole API:

// NewKeypair requests the creation of a new keypair for use with the Pigeonhole protocol.
// The reply type, is NewKeypairReply.
type NewKeypair struct {
	// QueryID is used for correlating this thin client request with the
	// thin client response.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`
	// Seed is the 32 byte seed used to derive the keypair.
	Seed []byte `cbor:"seed"`
}

// EncryptRead requests the encryption of a read operation for a given read capability.
type EncryptRead struct {
	// QueryID is used for correlating this thin client request with the
	// thin client response.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// ReadCap is the read capability that grants access to the channel.
	ReadCap *bacap.ReadCap `cbor:"read_cap"`

	// MessageBoxIndex specifies the starting read position for the channel.
	MessageBoxIndex *bacap.MessageBoxIndex `cbor:"message_box_index"`
}

// EncryptWrite requests the encryption of a write operation for a given write capability.
type EncryptWrite struct {
	// QueryID is used for correlating this thin client request with the
	// thin client response.
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
	// thin client response.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// ReadCap is the read capability that grants access to the channel.
	ReadCap *bacap.ReadCap `cbor:"read_cap"`

	// WriteCap is the write capability that grants access to the channel.
	WriteCap *bacap.WriteCap `cbor:"write_cap"`

	// MessageBoxIndex is the current message box index being operated on.
	MessageBoxIndex []byte `cbor:"message_box_index"`

	// ReplyIndex is the index of the reply that was actually used when processing.
	// This field is optional - if nil, the daemon will use the default reply index.
	ReplyIndex *uint8 `cbor:"reply_index,omitempty"`

	// EnvelopeDescriptor contains the serialized EnvelopeDescriptor that
	// contains the private key material needed to decrypt the envelope reply.
	EnvelopeDescriptor []byte `cbor:"envelope_descriptor"`

	// MessageCiphertext is the encrypted message ciphertext that should be sent
	MessageCiphertext []byte `cbor:"message_ciphertext"`

	// EnvelopeHash is the hash of the CourierEnvelope that was sent to the
	// mixnet and is used to resume the read operation.
	EnvelopeHash *[32]byte `cbor:"envelope_hash"`

	// NoRetryOnBoxIDNotFound controls whether BoxIDNotFound errors on reads
	// trigger automatic retries. By default (false), reads will retry up to
	// 10 times to handle replication lag. Set to true to get immediate
	// BoxIDNotFound error without retries.
	NoRetryOnBoxIDNotFound bool `cbor:"no_retry_on_box_id_not_found,omitempty"`

	// NoIdempotentBoxAlreadyExists controls whether BoxAlreadyExists errors on writes
	// are treated as idempotent success. By default (false), BoxAlreadyExists is treated
	// as success (the write already happened). Set to true to return BoxAlreadyExists
	// as an error instead.
	NoIdempotentBoxAlreadyExists bool `cbor:"no_idempotent_box_already_exists,omitempty"`
}

// CancelResendingEncryptedMessage requests the daemon to cancel resending an encrypted message.
type CancelResendingEncryptedMessage struct {
	// QueryID is used for correlating this thin client request with the
	// thin client response.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// EnvelopeHash is the hash of the CourierEnvelope to cancel resending.
	EnvelopeHash *[32]byte `cbor:"envelope_hash"`
}

// StartResendingCopyCommand requests the daemon to send a copy command to a courier
// with ARQ (automatic repeat request) for reliable delivery.
// The copy command instructs the courier to read data from a temporary channel
// and write it to the destination channel.
type StartResendingCopyCommand struct {
	// QueryID is used for correlating this thin client request with the
	// thin client response.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// WriteCap is the write capability for the temporary channel that contains
	// the data to be copied. The courier will derive a ReadCap from this
	// to read the data.
	WriteCap *bacap.WriteCap `cbor:"write_cap"`

	// CourierIdentityHash is optional. If set, the daemon will send the copy command
	// to this specific courier instead of selecting a random one.
	// This enables nested copy commands with different couriers per layer.
	CourierIdentityHash *[32]byte `cbor:"courier_identity_hash,omitempty"`

	// CourierQueueID is optional. Must be set if CourierIdentityHash is set.
	// This is the recipient queue ID for the specified courier.
	CourierQueueID []byte `cbor:"courier_queue_id,omitempty"`
}

// CancelResendingCopyCommand requests the daemon to cancel resending a copy command.
type CancelResendingCopyCommand struct {
	// QueryID is used for correlating this thin client request with the
	// thin client response.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// WriteCapHash is the hash of the WriteCap used in StartResendingCopyCommand.
	WriteCapHash *[32]byte `cbor:"write_cap_hash"`
}

// NextMessageBoxIndex requests the daemon to increment a MessageBoxIndex.
// This is used when sending multiple messages to different mailboxes using
// the same WriteCap. The reply type is NextMessageBoxIndexReply.
type NextMessageBoxIndex struct {
	// QueryID is used for correlating this thin client request with the
	// thin client response.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// MessageBoxIndex is the current index to increment.
	MessageBoxIndex *bacap.MessageBoxIndex `cbor:"message_box_index"`
}

// CreateCourierEnvelopesFromPayload creates multiple CourierEnvelopes from a payload of any size.
// The payload is automatically chunked and each chunk is wrapped in a CourierEnvelope.
// Each returned chunk is a serialized CopyStreamElement ready to be written to a box.
//
// This method is stateless — no daemon state is kept between calls. Each call creates
// a fresh encoder, encodes all envelopes, flushes, and returns. The caller controls
// the copy stream boundaries via IsStart and IsLast flags.
//
// Multiple calls can target the same destination stream by using NextDestIndex from
// the reply as the DestStartIndex for the next call.
type CreateCourierEnvelopesFromPayload struct {
	// QueryID is used for correlating this thin client request with the
	// thin client response.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// Payload is the data to be written (max 10MB).
	Payload []byte `cbor:"payload"`

	// DestWriteCap is the write capability for the destination channel.
	DestWriteCap *bacap.WriteCap `cbor:"dest_write_cap"`

	// DestStartIndex is the starting index in the destination channel.
	DestStartIndex *bacap.MessageBoxIndex `cbor:"dest_start_index"`

	// IsStart indicates whether this is the first call in a multi-call sequence.
	// When true, the first CopyStreamElement will have the IsStart flag set.
	IsStart bool `cbor:"is_start"`

	// IsLast indicates whether this is the last payload in the sequence.
	// When true, the final CopyStreamElement will have IsFinal=true.
	IsLast bool `cbor:"is_last"`
}

// CreateCourierEnvelopesFromTombstoneRange creates multiple CourierEnvelopes containing
// tombstones (empty payload with SignBox signatures) for a range of destination indices.
// Each returned chunk is a serialized CopyStreamElement ready to be written to a box.
//
// This is the tombstone equivalent of CreateCourierEnvelopesFromPayload: instead of
// chunking and encrypting a payload, it creates one tombstone CourierEnvelope per index
// in the range [DestStartIndex, DestStartIndex + MaxCount).
//
// The Buffer field enables stateless continuation: pass the Buffer from the previous
// call's reply to avoid wasting space in the last box of each call. On the first call,
// Buffer should be nil.
type CreateCourierEnvelopesFromTombstoneRange struct {
	// QueryID is used for correlating this thin client request with the
	// thin client response.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// DestWriteCap is the write capability for the destination channel.
	DestWriteCap *bacap.WriteCap `cbor:"dest_write_cap"`

	// DestStartIndex is the starting index in the destination channel.
	DestStartIndex *bacap.MessageBoxIndex `cbor:"dest_start_index"`

	// MaxCount is the number of tombstones to create.
	MaxCount uint32 `cbor:"max_count"`

	// IsStart indicates whether this is the first call in a multi-call sequence.
	// When true, the first CopyStreamElement will have the IsStart flag set.
	IsStart bool `cbor:"is_start"`

	// IsLast indicates whether this is the last call in the sequence.
	// When true, the final CopyStreamElement will have IsFinal=true.
	IsLast bool `cbor:"is_last"`

	// Buffer is the residual encoder buffer from a previous call.
	// Pass nil on the first call.
	Buffer []byte `cbor:"buffer"`
}

// DestinationPayload specifies a payload and its destination channel for multi-channel writes.
type DestinationPayload struct {
	// Payload is the data to be written to this destination.
	Payload []byte `cbor:"payload"`

	// WriteCap is the write capability for the destination channel.
	WriteCap *bacap.WriteCap `cbor:"write_cap"`

	// StartIndex is the starting index in the destination channel.
	StartIndex *bacap.MessageBoxIndex `cbor:"start_index"`
}

// CreateCourierEnvelopesFromPayloads creates CourierEnvelopes from multiple payloads
// going to different destination channels. This is more space-efficient than calling
// CreateCourierEnvelopesFromPayload multiple times because envelopes from different
// destinations are packed together in the copy stream without wasting space.
//
// This method is stateless — the Buffer field enables continuation across multiple
// calls without daemon-side state. Pass the Buffer from the previous call's reply
// to avoid wasting space in the last box of each call. On the first call, Buffer
// should be nil.
type CreateCourierEnvelopesFromPayloads struct {
	// QueryID is used for correlating this thin client request with the
	// thin client response.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// Destinations is the list of payloads and their destination channels.
	Destinations []DestinationPayload `cbor:"destinations"`

	// IsStart indicates whether this is the first call in a multi-call sequence.
	// When true, the first CopyStreamElement will have the IsStart flag set.
	IsStart bool `cbor:"is_start"`

	// IsLast indicates whether this is the last set of payloads in the sequence.
	// When true, the final CopyStreamElement will have IsFinal=true.
	IsLast bool `cbor:"is_last"`

	// Buffer is the residual encoder buffer from a previous call.
	// Pass nil on the first call.
	Buffer []byte `cbor:"buffer"`
}

// SendChannelQuery is used to send a Pigeonhole protocol ciphertext query payload
// through the mix network.
type SendChannelQuery struct {
	// MessageID is the unique identifier for the request associated with the
	// query reply.
	MessageID *[MessageIDLength]byte `cbor:"message_id"`

	// ChannelID is optional and only used for sending channel messages.
	// For non-channel messages, this field should be nil.
	ChannelID *uint16 `cbor:"channel_id,omitempty"`

	// DestinationIdHash is 32 byte hash of the destination Service's
	// identity public key.
	DestinationIdHash *[hash.HashSize]byte `cbor:"destination_id_hash"`

	// RecipientQueueID is the queue identity which will receive the message.
	// This queue ID is meant to be the queue ID of the Pigeonhole protocol Courier service.
	RecipientQueueID []byte `cbor:"recipient_queue_id"`

	// Payload is the Pigeonole protocol ciphertext payload which will be encapsulated in the Sphinx payload.
	Payload []byte `cbor:"payload"`
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

// SessionToken is sent by the thin client as its first request after the handshake.
type SessionToken struct {
	ClientInstanceToken [16]byte `cbor:"client_instance_token"`
}

// SessionTokenReply is the daemon's response to a SessionToken request.
type SessionTokenReply struct {
	AppID   []byte `cbor:"app_id"`
	Resumed bool   `cbor:"resumed"`
}

func (r *SessionTokenReply) String() string {
	return fmt.Sprintf("SessionTokenReply{Resumed: %v}", r.Resumed)
}

// ThinClose is used to indicate that the thin client is disconnecting
// from the daemon.
type ThinClose struct {
}

// Response is the client daemon's response message to the thin client.
type Response struct {

	SessionTokenReply *SessionTokenReply `cbor:"session_token_reply"`

	// ShutdownEvent is sent when the client daemon is shutting down.
	ShutdownEvent *ShutdownEvent `cbor:"shutdown_event"`

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

	// StartResendingCopyCommandReply is sent when the client daemon successfully sends a copy command with ARQ.
	StartResendingCopyCommandReply *StartResendingCopyCommandReply `cbor:"start_resending_copy_command_reply"`

	// CancelResendingCopyCommandReply is sent when the client daemon successfully cancels resending a copy command.
	CancelResendingCopyCommandReply *CancelResendingCopyCommandReply `cbor:"cancel_resending_copy_command_reply"`

	// NextMessageBoxIndexReply is sent when the client daemon successfully increments a MessageBoxIndex.
	NextMessageBoxIndexReply *NextMessageBoxIndexReply `cbor:"next_message_box_index_reply"`

	// Copy Channel API:

	// CreateCourierEnvelopesFromPayloadReply is sent when the client daemon successfully creates courier envelopes from a payload.
	CreateCourierEnvelopesFromPayloadReply *CreateCourierEnvelopesFromPayloadReply `cbor:"create_courier_envelopes_from_payload_reply"`

	// CreateCourierEnvelopesFromPayloadsReply is sent when the client daemon successfully creates courier envelopes from multiple payloads.
	CreateCourierEnvelopesFromPayloadsReply *CreateCourierEnvelopesFromPayloadsReply `cbor:"create_courier_envelopes_from_multi_payload_reply"`

	// CreateCourierEnvelopesFromTombstoneRangeReply is sent when the client daemon successfully
	// creates tombstone courier envelopes for a range of destination indices.
	CreateCourierEnvelopesFromTombstoneRangeReply *CreateCourierEnvelopesFromTombstoneRangeReply `cbor:"create_courier_envelopes_from_tombstone_range_reply"`
}

// Request is the thin client's request message to the client daemon.
// It can result in one or more Response messages being sent back to the thin client.
type Request struct {

	SessionToken *SessionToken `cbor:"session_token"`

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

	// StartResendingCopyCommand is used to send a copy command with ARQ.
	StartResendingCopyCommand *StartResendingCopyCommand `cbor:"start_resending_copy_command"`

	// CancelResendingCopyCommand is used to cancel resending a copy command.
	CancelResendingCopyCommand *CancelResendingCopyCommand `cbor:"cancel_resending_copy_command"`

	// NextMessageBoxIndex is used to increment a MessageBoxIndex.
	NextMessageBoxIndex *NextMessageBoxIndex `cbor:"next_message_box_index"`

	// CreateCourierEnvelopesFromPayload is used to create multiple CourierEnvelopes from a payload of any size.
	CreateCourierEnvelopesFromPayload *CreateCourierEnvelopesFromPayload `cbor:"create_courier_envelopes_from_payload"`

	// CreateCourierEnvelopesFromPayloads is used to create CourierEnvelopes from multiple payloads
	// going to different destination channels. This is more space-efficient than calling
	// CreateCourierEnvelopesFromPayload multiple times.
	CreateCourierEnvelopesFromPayloads *CreateCourierEnvelopesFromPayloads `cbor:"create_courier_envelopes_from_multi_payload"`

	// CreateCourierEnvelopesFromTombstoneRange is used to create tombstone CourierEnvelopes
	// for a range of destination indices, encoded as copy stream elements.
	CreateCourierEnvelopesFromTombstoneRange *CreateCourierEnvelopesFromTombstoneRange `cbor:"create_courier_envelopes_from_tombstone_range"`
}
