// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"fmt"
	"time"

	"github.com/katzenpost/hpqc/bacap"

	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
)

// ChannelIDLength is the length of the channel ID in bytes.
const ChannelIDLength = 32

// Event is the generic interface for all events sent by the thin client.
//
// Events are sent through channels returned by EventSink() and provide
// asynchronous notification of various client operations and status changes.
// Applications should use type assertions to handle specific event types.
//
// Common event types include:
//   - ConnectionStatusEvent: Connection state changes
//   - MessageReplyEvent: Replies to sent messages
//   - NewDocumentEvent: PKI document updates
//   - Channel operation events (CreateWriteChannelReply, etc.)
type Event interface {
	// String returns a human-readable string representation of the Event.
	String() string
}

// ShutdownEvent is sent when the client daemon is shutting down.
//
// This event indicates that the daemon is terminating and the thin client
// connection will be lost. Applications should handle this event by
// performing cleanup and potentially attempting to reconnect.
type ShutdownEvent struct{}

// String returns a string representation of the ShutdownEvent.
func (e *ShutdownEvent) String() string {
	return "ShutdownEvent"
}

// ConnectionStatusEvent is sent when the daemon's connection status changes.
//
// This event indicates whether the client daemon is currently connected to
// the mixnet infrastructure. When IsConnected is false, the client operates
// in "offline mode" where channel preparation operations work but actual
// message transmission will fail.
//
// Applications can use this event to:
//   - Display connection status to users
//   - Queue operations for later transmission when offline
//   - Implement retry logic for failed operations
type ConnectionStatusEvent struct {
	// IsConnected indicates whether the daemon is connected to the mixnet.
	// When true, full functionality is available. When false, only offline
	// operations (channel preparation) will work.
	IsConnected bool `cbor:"is_connected"`

	// Err contains any error that caused a disconnection. This field is
	// nil when IsConnected is true or when the disconnection was intentional.
	Err error `cbor:"err"`
}

// String returns a string representation of the ConnectionStatusEvent.
func (e *ConnectionStatusEvent) String() string {
	if !e.IsConnected {
		return fmt.Sprintf("ConnectionStatus: %v (%v)", e.IsConnected, e.Err)
	}
	return fmt.Sprintf("ConnectionStatus: %v", e.IsConnected)
}

// MessageReplyEvent is the event sent when a new message is received.
type MessageReplyEvent struct {
	// MessageID is the unique identifier for the request associated with the
	// reply.
	MessageID *[MessageIDLength]byte `cbor:"message_id"`

	// SURBID must be a unique identity for each request.
	// This field should be nil if WithSURB is false.
	SURBID *[constants.SURBIDLength]byte `cbor:"surbid"`

	// Payload is the reply payload if any.
	Payload []byte `cbor:"payload"`

	// ReplyIndex is the index of the reply that was actually used when processing
	// this message. This is particularly relevant for pigeonhole channel reads.
	ReplyIndex *uint8 `cbor:"reply_index,omitempty"`

	// ErrorCode indicates the success or failure of the message operation.
	// A value of ThinClientSuccess (0) indicates no error occurred.
	// Non-zero values indicate specific error conditions.
	ErrorCode uint8 `cbor:"error_code"`
}

// String returns a string representation of the MessageReplyEvent.
func (e *MessageReplyEvent) String() string {
	replyIndexStr := ""
	if e.ReplyIndex != nil {
		replyIndexStr = fmt.Sprintf(" replyIndex=%d", *e.ReplyIndex)
	}
	if e.ErrorCode != ThinClientSuccess {
		return fmt.Sprintf("MessageReply: %x %s failed: %s", e.MessageID[:], replyIndexStr, ThinClientErrorToString(e.ErrorCode))
	}
	return fmt.Sprintf("KaetzchenReply: %x %s (%v bytes)", e.MessageID[:], replyIndexStr, len(e.Payload))
}

// MessageSentEvent is the event sent when a message has been fully transmitted.
type MessageSentEvent struct {
	// MessageID is the local unique identifier for the message, generated
	// when the message was enqueued.
	MessageID *[MessageIDLength]byte `cbor:"message_id"`

	// SURBID must be a unique identity for each request.
	// This field should be nil if WithSURB is false.
	SURBID *[constants.SURBIDLength]byte `cbor:"surbid"`

	// SentAt contains the time the message was sent.
	SentAt time.Time `cbor:"sent_at"`

	// ReplyETA is the expected round trip time to receive a response.
	ReplyETA time.Duration `cbor:"reply_eta"`

	// Err is the error message if any error was encountered when sending the message.
	// Empty string indicates no error occurred.
	Err string `cbor:"err,omitempty"`
}

// String returns a string representation of a MessageSentEvent.
func (e *MessageSentEvent) String() string {
	if e.Err != "" {
		return fmt.Sprintf("MessageSent: %x failed: %v", e.MessageID[:], e.Err)
	}
	return fmt.Sprintf("MessageSent: %x", e.MessageID[:])
}

// MessageIDGarbageCollected is the event used to signal when a given
// message ID has been garbage collected.
type MessageIDGarbageCollected struct {
	// MessageID is the local unique identifier for the message.
	MessageID *[MessageIDLength]byte `cbor:"message_id"`
}

// String returns a string representation of a MessageIDGarbageCollected.
func (e *MessageIDGarbageCollected) String() string {
	return fmt.Sprintf("MessageIDGarbageCollected: %x", e.MessageID[:])
}

// NewDocumentEvent is the new document event, signaling that
// we have received a new document from the PKI.
type NewDocumentEvent struct {
	Document *cpki.Document `cbor:"document"`
}

// String returns a string representation of a NewDocumentEvent.
func (e *NewDocumentEvent) String() string {
	return fmt.Sprintf("PKI Document for epoch %d", e.Document.Epoch)
}

// NewPKIDocumentEvent is the unix domain socket protocol message used
// by the daemon to tell the thin client about new PKI document events.
// The payload field contains a CBOR encoded PKI document, stripped of signatures.
type NewPKIDocumentEvent struct {
	Payload []byte `cbor:"payload"`
}

// String returns a string representation of a NewDocumentEvent.
func (e *NewPKIDocumentEvent) String() string {
	doc, err := cpki.ParseDocument(e.Payload)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("PKI Document for epoch %d", doc.Epoch)
}

/**** NEW API ***/

// CreateWriteChannelReply is sent in response to a CreateWriteChannel request.
// It provides the channel ID and capabilities needed to use the newly created
// or resumed pigeonhole write channel.
type CreateWriteChannelReply struct {
	// QueryID is used for correlating this reply with the CreateWriteChannel request
	// that created it.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// ChannelID is the unique identifier for the created channel, used in
	// subsequent WriteChannel operations.
	ChannelID uint16 `cbor:"channel_id"`

	// ReadCap is the read capability that can be shared with others to allow
	// them to read messages from this channel.
	ReadCap *bacap.ReadCap `cbor:"read_cap"`

	// WriteCap is the write capability that should be stored for channel
	// persistence and resumption across client restarts.
	WriteCap *bacap.WriteCap `cbor:"write_cap"`

	// ErrorCode indicates the success or failure of the channel creation.
	// A value of ThinClientErrorSuccess indicates successful creation.
	ErrorCode uint8 `cbor:"error_code"`
}

// String returns a string representation of the CreateWriteChannelReply.
func (e *CreateWriteChannelReply) String() string {
	if e.ErrorCode != ThinClientSuccess {
		return fmt.Sprintf("CreateWriteChannelReply: %d (error: %s)", e.ChannelID, ThinClientErrorToString(e.ErrorCode))
	}
	return fmt.Sprintf("CreateWriteChannelReply: %d", e.ChannelID)
}

// CreateReadChannelReply is sent in response to a CreateReadChannel request.
// It provides the channel ID and current read position for the newly created
// pigeonhole read channel.
type CreateReadChannelReply struct {
	// QueryID is used for correlating this reply with the CreateReadChannel request
	// that created it.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// ChannelID is the unique identifier for the created read channel, used in
	// subsequent ReadChannel operations.
	ChannelID uint16 `cbor:"channel_id"`

	// ErrorCode indicates the success or failure of the channel creation.
	// A value of ThinClientErrorSuccess indicates successful creation.
	ErrorCode uint8 `cbor:"error_code"`
}

// String returns a string representation of the CreateReadChannelReply.
func (e *CreateReadChannelReply) String() string {
	if e.ErrorCode != ThinClientSuccess {
		return fmt.Sprintf("CreateReadChannelReply: %d (error: %s)", e.ChannelID, ThinClientErrorToString(e.ErrorCode))
	}
	return fmt.Sprintf("CreateReadChannelReply: %d", e.ChannelID)
}

// WriteChannelReply is sent in response to a WriteChannel request.
// It provides the prepared message payload that should be sent through the mixnet
// to complete the channel write operation.
type WriteChannelReply struct {
	// QueryID is used for correlating this reply with the WriteChannel request
	// that created it.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// ChannelID identifies the channel this reply corresponds to.
	ChannelID uint16 `cbor:"channel_id"`

	// SendMessagePayload contains the prepared Sphinx packet that should be
	// sent via SendChannelQuery to complete the write operation.
	SendMessagePayload []byte `cbor:"send_message_payload"`

	// CurrentMessageIndex indicates the message index for the current message.
	CurrentMessageIndex *bacap.MessageBoxIndex `cbor:"current_message_index"`

	// NextMessageIndex indicates the message index to use after the courier
	// acknowledges successful delivery of this message.
	NextMessageIndex *bacap.MessageBoxIndex `cbor:"next_message_index"`

	// EnvelopeHash is the hash of the CourierEnvelope that was sent to the
	EnvelopeHash *[32]byte `cbor:"envelope_hash"`

	// EnvelopeDescriptor contains the serialized EnvelopeDescriptor that
	// contains the private key material needed to decrypt the envelope reply.
	EnvelopeDescriptor []byte `cbor:"envelope_descriptor"`

	// ErrorCode indicates the success or failure of preparing the write operation.
	// A value of ThinClientErrorSuccess indicates the payload is ready to send.
	ErrorCode uint8 `cbor:"error_code"`
}

// String returns a string representation of the WriteChannelReply.
func (e *WriteChannelReply) String() string {
	if e.ErrorCode != ThinClientSuccess {
		return fmt.Sprintf("WriteChannelReply: %d (error: %s)", e.ChannelID, ThinClientErrorToString(e.ErrorCode))
	}
	return fmt.Sprintf("WriteChannelReply: %d (%d bytes payload)", e.ChannelID, len(e.SendMessagePayload))
}

// ReadChannelReply is sent in response to a ReadChannel request.
// It provides the prepared query payload that should be sent through the mixnet
// to retrieve the next message from the channel.
type ReadChannelReply struct {
	// QueryID is used for correlating this reply with the ReadChannel request
	// that created it.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// ChannelID identifies the channel this reply corresponds to.
	ChannelID uint16 `cbor:"channel_id"`

	// ErrorCode indicates the success or failure of preparing the read operation.
	// A value of ThinClientErrorSuccess indicates the query is ready to send.
	ErrorCode uint8 `cbor:"error_code"`

	// SendMessagePayload contains the prepared query that should be sent via
	// SendChannelQuery to retrieve the next message from the channel.
	SendMessagePayload []byte `cbor:"send_message_payload"`

	// CurrentMessageIndex indicates the message index for the current message.
	CurrentMessageIndex *bacap.MessageBoxIndex `cbor:"current_message_index"`

	// NextMessageIndex indicates the message index to use after successfully
	// reading the current message.
	NextMessageIndex *bacap.MessageBoxIndex `cbor:"next_message_index"`

	// ReplyIndex is the index of the reply that was used when creating this ReadChannelReply.
	// This corresponds to the ReplyIndex parameter from the ReadChannel request.
	ReplyIndex *uint8 `cbor:"reply_index"`

	// EnvelopeHash is the hash of the CourierEnvelope that was sent to the
	// mixnet and is used to resume the read operation.
	EnvelopeHash *[32]byte `cbor:"envelope_hash"`

	// EnvelopeDescriptor contains the serialized EnvelopeDescriptor that
	// contains the private key material needed to decrypt the envelope reply.
	EnvelopeDescriptor []byte `cbor:"envelope_descriptor"`
}

// String returns a string representation of the ReadChannelReply.
func (e *ReadChannelReply) String() string {
	msgIDStr := "nil"
	if e.QueryID != nil {
		msgIDStr = fmt.Sprintf("%x", e.QueryID)
	}
	replyIndexStr := ""
	if e.ReplyIndex != nil {
		replyIndexStr = fmt.Sprintf(" replyIndex=%d", *e.ReplyIndex)
	}
	if e.ErrorCode != ThinClientSuccess {
		return fmt.Sprintf("ReadChannelReply: msgID=%s channel=%d%s (error: %s)", msgIDStr, e.ChannelID, replyIndexStr, ThinClientErrorToString(e.ErrorCode))
	}
	return fmt.Sprintf("ReadChannelReply: msgID=%s channel=%d%s (%d bytes payload)", msgIDStr, e.ChannelID, replyIndexStr, len(e.SendMessagePayload))
}

// ResumeWriteChannelReply is sent in response to a ResumeWriteChannel request.
// It indicates whether the resume operation was successful or not.
type ResumeWriteChannelReply struct {
	// QueryID is used for correlating this reply with the ResumeWriteChannel request
	// that created it.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// ChannelID is the unique identifier for the resumed channel, used in
	// subsequent WriteChannel operations.
	ChannelID uint16 `cbor:"channel_id"`

	// ErrorCode indicates the success or failure of preparing the write operation
	// resumption. A value of ThinClientErrorSuccess indicates the payload is ready
	// to send in a subsequent SendChannelQuery call.
	ErrorCode uint8 `cbor:"error_code"`
}

// String returns a string representation of the ResumeWriteChannelReply.
func (e *ResumeWriteChannelReply) String() string {
	msgIDStr := "nil"
	if e.QueryID != nil {
		msgIDStr = fmt.Sprintf("%x", e.QueryID)
	}
	if e.ErrorCode != ThinClientSuccess {
		return fmt.Sprintf("ResumeWriteChannelReply: msgID=%s (error: %s)", msgIDStr, ThinClientErrorToString(e.ErrorCode))
	}
	return fmt.Sprintf("ResumeWriteChannelReply: msgID=%s", msgIDStr)
}

// ResumeWriteChannelReply is sent in response to a ResumeWriteChannel request.
// It indicates whether the resume operation was successful or not.
type ResumeWriteChannelQueryReply struct {
	// QueryID is used for correlating this reply with the ResumeWriteChannel request
	// that created it.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// ChannelID is the unique identifier for the resumed channel, used in
	// subsequent WriteChannel operations.
	ChannelID uint16 `cbor:"channel_id"`

	// ErrorCode indicates the success or failure of preparing the write operation
	// resumption. A value of ThinClientErrorSuccess indicates the payload is ready
	// to send in a subsequent SendChannelQuery call.
	ErrorCode uint8 `cbor:"error_code"`
}

// String returns a string representation of the ResumeWriteChannelReply.
func (e *ResumeWriteChannelQueryReply) String() string {
	msgIDStr := "nil"
	if e.QueryID != nil {
		msgIDStr = fmt.Sprintf("%x", e.QueryID)
	}
	if e.ErrorCode != ThinClientSuccess {
		return fmt.Sprintf("ResumeWriteChannelReply: msgID=%s (error: %s)", msgIDStr, ThinClientErrorToString(e.ErrorCode))
	}
	return fmt.Sprintf("ResumeWriteChannelReply: msgID=%s", msgIDStr)
}

// ResumeReadChannelReply is sent in response to a ResumeReadChannel request.
// It indicates whether the resume operation was successful or not.
type ResumeReadChannelReply struct {
	// QueryID is used for correlating this reply with the ResumeReadChannel request
	// that created it.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// ChannelID is the unique identifier for the resumed channel, used in
	// subsequent ReadChannel operations.
	ChannelID uint16 `cbor:"channel_id"`

	// ErrorCode indicates the success or failure of preparing the read operation
	// resumption. A value of ThinClientErrorSuccess indicates the query is ready
	// to send in a subsequent SendChannelQuery call.
	ErrorCode uint8 `cbor:"error_code"`
}

// String returns a string representation of the ResumeReadChannelReply.
func (e *ResumeReadChannelReply) String() string {
	msgIDStr := "nil"
	if e.QueryID != nil {
		msgIDStr = fmt.Sprintf("%x", e.QueryID)
	}
	if e.ErrorCode != ThinClientSuccess {
		return fmt.Sprintf("ResumeReadChannelReply: msgID=%s (error: %s)", msgIDStr, ThinClientErrorToString(e.ErrorCode))
	}
	return fmt.Sprintf("ResumeReadChannelReply: msgID=%s", msgIDStr)
}

// ResumeReadChannelReply is sent in response to a ResumeReadChannel request.
// It indicates whether the resume operation was successful or not.
type ResumeReadChannelQueryReply struct {
	// QueryID is used for correlating this reply with the ResumeReadChannel request
	// that created it.
	QueryID *[QueryIDLength]byte `cbor:"query_id"`

	// ChannelID is the unique identifier for the resumed channel, used in
	// subsequent ReadChannel operations.
	ChannelID uint16 `cbor:"channel_id"`

	// ErrorCode indicates the success or failure of preparing the read operation
	// resumption. A value of ThinClientErrorSuccess indicates the query is ready
	// to send in a subsequent SendChannelQuery call.
	ErrorCode uint8 `cbor:"error_code"`
}

// String returns a string representation of the ResumeReadChannelReply.
func (e *ResumeReadChannelQueryReply) String() string {
	msgIDStr := "nil"
	if e.QueryID != nil {
		msgIDStr = fmt.Sprintf("%x", e.QueryID)
	}
	if e.ErrorCode != ThinClientSuccess {
		return fmt.Sprintf("ResumeReadChannelReply: msgID=%s (error: %s)", msgIDStr, ThinClientErrorToString(e.ErrorCode))
	}
	return fmt.Sprintf("ResumeReadChannelReply: msgID=%s", msgIDStr)
}

// ChannelQuerySentEvent is the event sent when a message has been fully transmitted.
type ChannelQuerySentEvent struct {
	// MessageID is the unique identifier for the request associated with the
	// query sent in the SendChannelQuery command.
	MessageID *[MessageIDLength]byte `cbor:"message_id"`

	// SentAt contains the time the message was sent.
	SentAt time.Time `cbor:"sent_at"`

	// ReplyETA is the expected round trip time to receive a response.
	ReplyETA time.Duration `cbor:"reply_eta"`

	// ErrorCode indicates the success or failure of sending the channel query.
	// A value of ThinClientErrorSuccess indicates the query was successfully sent.
	ErrorCode uint8 `cbor:"error_code"`
}

// String returns a string representation of a MessageSentEvent.
func (e *ChannelQuerySentEvent) String() string {
	if e.ErrorCode != ThinClientSuccess {
		return fmt.Sprintf("ChannelQuerySentEvent: %x failed: %s", e.MessageID[:], ThinClientErrorToString(e.ErrorCode))
	}
	return fmt.Sprintf("ChannelQuerySentEvent: %x", e.MessageID[:])
}

// ChannelQueryReplyEvent is the event sent when a new message is received.
type ChannelQueryReplyEvent struct {
	// MessageID is the unique identifier for the request associated with the
	// query sent in the SendChannelQuery command.
	MessageID *[MessageIDLength]byte `cbor:"message_id"`

	// Payload is the reply payload if any.
	Payload []byte `cbor:"payload"`

	// ReplyIndex is the index of the reply that was actually used when processing
	// this message. This is particularly relevant for pigeonhole channel reads.
	ReplyIndex *uint8 `cbor:"reply_index"`

	// ErrorCode indicates the success or failure of sending the channel query.
	// A value of ThinClientErrorSuccess indicates the query was successfully sent.
	ErrorCode uint8 `cbor:"error_code"`
}

// String returns a string representation of the ChannelQueryReplyEvent.
func (e *ChannelQueryReplyEvent) String() string {
	if e.ErrorCode != ThinClientSuccess {
		return fmt.Sprintf("ChannelQueryReplyEvent: msgID=%x (error: %s)", e.MessageID[:], ThinClientErrorToString(e.ErrorCode))
	}
	return fmt.Sprintf("ChannelQueryReplyEvent: msgID=%x", e.MessageID[:])
}
