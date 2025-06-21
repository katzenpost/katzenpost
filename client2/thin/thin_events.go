// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package thin provides event types and error codes for the thin client protocol.
// This file defines the event system used for asynchronous communication between
// the thin client and applications, as well as standardized error codes for
// consistent error handling across the protocol.
package thin

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/katzenpost/hpqc/bacap"

	cpki "github.com/katzenpost/katzenpost/core/pki"
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

// Event is the generic interface for all events sent through the thin client's
// event system. Events provide asynchronous notifications about connection status,
// message delivery, responses, and other protocol activities.
//
// All event types implement this interface to provide consistent string
// representation for logging and debugging purposes.
type Event interface {
	// String returns a human-readable string representation of the event.
	// This is used for logging, debugging, and display purposes.
	String() string
}

// ShutdownEvent is sent when the thin client or daemon is shutting down.
// Applications should handle this event by performing cleanup and terminating
// gracefully. No further events will be sent after a ShutdownEvent.
type ShutdownEvent struct{}

// String returns a string representation of the ShutdownEvent.
func (e *ShutdownEvent) String() string {
	return "ShutdownEvent"
}

// ConnectionStatusEvent is sent when the client's connection status to the
// mixnet daemon changes. This event indicates whether the client is currently
// connected and able to send/receive messages through the mixnet.
//
// Applications should monitor these events to understand connectivity state
// and handle connection failures appropriately.
type ConnectionStatusEvent struct {
	// IsConnected indicates whether the client is currently connected to the
	// mixnet entry node. When true, the client can send and receive messages.
	// When false, the client is disconnected and operations will fail.
	IsConnected bool `cbor:"is_connected"`

	// Err contains any error that occurred during connection establishment or
	// that caused a disconnection. This field is nil when IsConnected is true
	// or when the disconnection was intentional.
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
	SURBID *[sConstants.SURBIDLength]byte `cbor:"surbid"`

	// Payload is the reply payload if any.
	Payload []byte `cbor:"payload"`

	// ErrorCode is the error code encountered when servicing the request if any.
	ErrorCode uint8 `cbor:"error_code,omitempty"`
}

// String returns a string representation of the MessageReplyEvent.
func (e *MessageReplyEvent) String() string {
	if e.ErrorCode != ThinClientSuccess {
		return fmt.Sprintf("MessageReply: %v failed: %v", hex.EncodeToString(e.MessageID[:]), ThinClientErrorToString(e.ErrorCode))
	}
	return fmt.Sprintf("KaetzchenReply: %v (%v bytes)", hex.EncodeToString(e.MessageID[:]), len(e.Payload))
}

// MessageSentEvent is the event sent when a message has been fully transmitted.
type MessageSentEvent struct {
	// MessageID is the local unique identifier for the message, generated
	// when the message was enqueued.
	MessageID *[MessageIDLength]byte `cbor:"message_id"`

	// SURBID must be a unique identity for each request.
	// This field should be nil if WithSURB is false.
	SURBID *[sConstants.SURBIDLength]byte `cbor:"surbid"`

	// SentAt contains the time the message was sent.
	SentAt time.Time `cbor:"sent_at"`

	// ReplyETA is the expected round trip time to receive a response.
	ReplyETA time.Duration `cbor:"reply_eta"`

	// ErrorCode is the error code encountered when sending the message if any.
	ErrorCode uint8 `cbor:"error_code,omitempty"`
}

// String returns a string representation of a MessageSentEvent.
func (e *MessageSentEvent) String() string {
	if e.ErrorCode != ThinClientSuccess {
		return fmt.Sprintf("MessageSent: %v failed: %v", hex.EncodeToString(e.MessageID[:]), ThinClientErrorToString(e.ErrorCode))
	}
	return fmt.Sprintf("MessageSent: %v", hex.EncodeToString(e.MessageID[:]))
}

// MessageIDGarbageCollected is the event used to signal when a given
// message ID has been garbage collected.
type MessageIDGarbageCollected struct {
	// MessageID is the local unique identifier for the message.
	MessageID *[MessageIDLength]byte `cbor:"message_id"`
}

// String returns a string representation of a MessageIDGarbageCollected.
func (e *MessageIDGarbageCollected) String() string {
	return fmt.Sprintf("MessageIDGarbageCollected: %v", hex.EncodeToString(e.MessageID[:]))
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

// NewPKIDocumentEvent is sent when the daemon receives an updated PKI document
// from the mixnet. This event provides the thin client with current network topology
// and service information needed for routing messages through the mixnet.
//
// The client should update its internal PKI state when receiving this event to
// ensure messages are routed using the most current network information.
type NewPKIDocumentEvent struct {
	// Payload contains the CBOR-encoded PKI document with cryptographic signatures
	// removed for size optimization. The document includes network topology,
	// service descriptors, and routing information for the current epoch.
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

// CreateWriteChannelReply is sent in response to a CreateWriteChannel request.
// It provides the channel ID and capabilities needed to use the newly created
// or resumed pigeonhole write channel.
type CreateWriteChannelReply struct {
	// ChannelID is the unique identifier for the created channel, used in
	// subsequent WriteChannel operations.
	ChannelID uint16 `cbor:"channel_id"`

	// ReadCap is the read capability that can be shared with others to allow
	// them to read messages from this channel.
	ReadCap *bacap.ReadCap `cbor:"read_cap"`

	// WriteCap is the write capability that should be stored for channel
	// persistence and resumption across client restarts.
	WriteCap *bacap.WriteCap `cbor:"write_cap"`

	// NextMessageIndex indicates the current write position in the channel,
	// used for tracking message ordering and resumption.
	NextMessageIndex *bacap.MessageBoxIndex `cbor:"next_message_index"`

	// ErrorCode indicates the success or failure of the channel creation.
	// A value of ThinClientErrorSuccess indicates successful creation.
	ErrorCode uint8 `cbor:"error_code,omitempty"`
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
	// ChannelID is the unique identifier for the created read channel, used in
	// subsequent ReadChannel operations.
	ChannelID uint16 `cbor:"channel_id"`

	// NextMessageIndex indicates the current read position in the channel,
	// showing where the next read operation will start from.
	NextMessageIndex *bacap.MessageBoxIndex `cbor:"next_message_index"`

	// ErrorCode indicates the success or failure of the channel creation.
	// A value of ThinClientErrorSuccess indicates successful creation.
	ErrorCode uint8 `cbor:"error_code,omitempty"`
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
	// ChannelID identifies the channel this reply corresponds to.
	ChannelID uint16 `cbor:"channel_id"`

	// SendMessagePayload contains the prepared Sphinx packet that should be
	// sent via SendMessage to complete the write operation.
	SendMessagePayload []byte `cbor:"send_message_payload"`

	// NextMessageIndex indicates the message index to use after the courier
	// acknowledges successful delivery of this message.
	NextMessageIndex *bacap.MessageBoxIndex `cbor:"next_message_index"`

	// ErrorCode indicates the success or failure of preparing the write operation.
	// A value of ThinClientErrorSuccess indicates the payload is ready to send.
	ErrorCode uint8 `cbor:"error_code,omitempty"`
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
	// MessageID is used for correlating this read operation with its eventual
	// response when the query completes.
	MessageID *[MessageIDLength]byte `cbor:"message_id"`

	// ChannelID identifies the channel this reply corresponds to.
	ChannelID uint16 `cbor:"channel_id"`

	// SendMessagePayload contains the prepared query that should be sent via
	// SendMessage to retrieve the next message from the channel.
	SendMessagePayload []byte `cbor:"send_message_payload"`

	// NextMessageIndex indicates the message index to use after successfully
	// reading the current message.
	NextMessageIndex *bacap.MessageBoxIndex `cbor:"next_message_index"`

	// ErrorCode indicates the success or failure of preparing the read operation.
	// A value of ThinClientErrorSuccess indicates the query is ready to send.
	ErrorCode uint8 `cbor:"error_code,omitempty"`
}

// String returns a string representation of the ReadChannelReply.
func (e *ReadChannelReply) String() string {
	msgIDStr := "nil"
	if e.MessageID != nil {
		msgIDStr = fmt.Sprintf("%x", e.MessageID[:8]) // First 8 bytes for brevity
	}
	if e.ErrorCode != ThinClientSuccess {
		return fmt.Sprintf("ReadChannelReply: msgID=%s channel=%d (error: %s)", msgIDStr, e.ChannelID, ThinClientErrorToString(e.ErrorCode))
	}
	return fmt.Sprintf("ReadChannelReply: msgID=%s channel=%d (%d bytes payload)", msgIDStr, e.ChannelID, len(e.SendMessagePayload))
}

// CopyChannelReply is sent in response to a CopyChannel request.
// It indicates the success or failure of the channel copy operation to
// storage replicas via the courier system.
type CopyChannelReply struct {
	// ChannelID identifies the channel this reply corresponds to.
	ChannelID uint16 `cbor:"channel_id"`

	// ErrorCode indicates the success or failure of the copy operation.
	// A value of ThinClientErrorSuccess indicates successful copying.
	ErrorCode uint8 `cbor:"error_code,omitempty"`
}

// String returns a string representation of the CopyChannelReply.
func (e *CopyChannelReply) String() string {
	if e.ErrorCode != ThinClientSuccess {
		return fmt.Sprintf("CopyChannelReply: %d (error: %s)", e.ChannelID, ThinClientErrorToString(e.ErrorCode))
	}
	return fmt.Sprintf("CopyChannelReply: %d", e.ChannelID)
}
