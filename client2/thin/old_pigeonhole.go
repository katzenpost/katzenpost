// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
)

// OLD Pigeonhole API:

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

	// QueryID is used for correlating this thin client request with the
	// thin client reponse.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// ChannelID identifies the target channel for the write operation.
	// This ID was returned when the channel was created.
	ChannelID uint16 `cbor:"channel_id"`

	// Payload contains the message data to write to the channel.
	// The payload size must not exceed the channel's configured limits.
	Payload []byte `cbor:"payload"`
}

// ResumeWriteChannel requests resuming a write channel that was previously
// either written to or created but not yet written to. This command cannot
// resume a write operation that was in progress, for that you must used the
// ResumeWriteChannelQuery command instead.
type ResumeWriteChannel struct {

	// QueryID is used for correlating this thin client request with the
	// thin client reponse.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// WriteCap is the write capability for resuming an existing channel.
	// If nil, a new channel will be created. If provided, the channel will
	// be resumed from the specified MessageBoxIndex position.
	WriteCap *bacap.WriteCap `cbor:"write_cap,omitempty"`

	// MessageBoxIndex specifies the starting or resume point for the channel.
	// This field is can be nil when resuming a write channel which has not
	// yet been written to. If this field is provided, it is used to resume
	// the write channel from a specific message index. You must populate this
	// field with the NextMessageIndex from the previous WriteChannelReply.
	MessageBoxIndex *bacap.MessageBoxIndex `cbor:"message_box_index,omitempty"`
}

// ResumeWriteChannel requests resuming a write operation that was previously
// initiated but not yet completed.
type ResumeWriteChannelQuery struct {

	// QueryID is used for correlating this thin client request with the
	// thin client reponse.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// WriteCap is the write capability for resuming an existing channel.
	// If nil, a new channel will be created. If provided, the channel will
	// be resumed from the specified MessageBoxIndex position.
	WriteCap *bacap.WriteCap `cbor:"write_cap,omitempty"`

	// MessageBoxIndex specifies the resume point for the channel.
	// This field is required.
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
// Note that the last two fields are useful if you want to send two read queries
// to the same Box id in order to retrieve two different replies.
type ReadChannel struct {
	// ChannelID identifies the source channel for the read operation.
	// This ID was returned when the channel was created.
	ChannelID uint16 `cbor:"channel_id"`

	// QueryID is used for correlating this thin client request with the
	// thin client reponse.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// MessageBoxIndex specifies the starting read position for the channel.
	// If this field is nil, reading will start from the current index in the client daemon's
	// stateful reader, which is what you want most of the time.
	// This field and the next field, ReplyIndex are complicated to use properly, like so:
	//
	// This field is only needed because the next field, ReplyIndex, requires us to
	// specify *which* message should be returned, since presumably the application
	// will perform two read queries *on the same Box* if the first result is not available.
	MessageBoxIndex *bacap.MessageBoxIndex `cbor:"message_box_index,omitempty"`

	// ReplyIndex is the index of the reply to return. It is optional and
	// a default of zero will be used if not specified.
	ReplyIndex *uint8 `cbor:"reply_index"`
}

// ResumeReadChannel requests resuming a read operation that was previously
// initiated but not yet completed.
type ResumeReadChannel struct {
	// QueryID is used for correlating this thin client request with the
	// thin client reponse.
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
	// QueryID is used for correlating this thin client request with the
	// thin client reponse.
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

// CloseChannel requests closing a pigeonhole channel. NOTE however that there
// is no corresponding reply type for this request to tell us if the close failed
// or not.
type CloseChannel struct {
	ChannelID uint16 `cbor:"channel_id"`
}

// SendChannelQuery is used to send a Pigeonhole protocol ciphertext query payload
// through the mix network. The result of sending this message type is two more events:
// ChannelQuerySentEvent and ChannelQueryReplyEvent both of which can be matched
// by the MessageID field.
type SendChannelQuery struct {
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
	// This queue ID is meant to be the queue ID of the Pigeonhole protocol Courier service.
	RecipientQueueID []byte `cbor:"recipient_queue_id"`

	// Payload is the Pigeonole protocol ciphertext payload which will be encapsulated in the Sphinx payload.
	Payload []byte `cbor:"payload"`
}
