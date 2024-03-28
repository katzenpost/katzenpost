// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"encoding/hex"
	"fmt"
	"time"

	cpki "github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

// Event is the generic event sent over the event listener channel.
type Event interface {
	// String returns a string representation of the Event.
	String() string
}

// ConnectionStatusEvent is the event sent when an account's connection status
// changes.
type ConnectionStatusEvent struct {
	// IsConnected is true iff the client is connected to the entry node.
	IsConnected bool `cbor:is_connected`

	// Err is the error encountered when connecting or by the connection if any.
	Err error `cbor:err`
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
	MessageID *[MessageIDLength]byte `cbor:message_id`

	// SURBID must be a unique identity for each request.
	// This field should be nil if WithSURB is false.
	SURBID *[sConstants.SURBIDLength]byte `cbor:surbid`

	// Payload is the reply payload if any.
	Payload []byte `cbor:payload`

	// Err is the error encountered when servicing the request if any.
	Err error `cbor:err`
}

// String returns a string representation of the MessageReplyEvent.
func (e *MessageReplyEvent) String() string {
	if e.Err != nil {
		return fmt.Sprintf("MessageReply: %v failed: %v", hex.EncodeToString(e.MessageID[:]), e.Err)
	}
	return fmt.Sprintf("KaetzchenReply: %v (%v bytes)", hex.EncodeToString(e.MessageID[:]), len(e.Payload))
}

// MessageSentEvent is the event sent when a message has been fully transmitted.
type MessageSentEvent struct {
	// MessageID is the local unique identifier for the message, generated
	// when the message was enqueued.
	MessageID *[MessageIDLength]byte `cbor:message_id`

	// SURBID must be a unique identity for each request.
	// This field should be nil if WithSURB is false.
	SURBID *[sConstants.SURBIDLength]byte `cbor:surbid`

	// SentAt contains the time the message was sent.
	SentAt time.Time `cbor:sent_at`

	// ReplyETA is the expected round trip time to receive a response.
	ReplyETA time.Duration `cbor:reply_eta`

	// Err is the error encountered when sending the message if any.
	Err error `cbor:err`
}

// String returns a string representation of a MessageSentEvent.
func (e *MessageSentEvent) String() string {
	if e.Err != nil {
		return fmt.Sprintf("MessageSent: %v failed: %v", hex.EncodeToString(e.MessageID[:]), e.Err)
	}
	return fmt.Sprintf("MessageSent: %v", hex.EncodeToString(e.MessageID[:]))
}

// MessageIDGarbageCollected is the event used to signal when a given
// message ID has been garbage collected.
type MessageIDGarbageCollected struct {
	// MessageID is the local unique identifier for the message.
	MessageID *[MessageIDLength]byte `cbor:message_id`
}

// String returns a string representation of a MessageIDGarbageCollected.
func (e *MessageIDGarbageCollected) String() string {
	return fmt.Sprintf("MessageIDGarbageCollected: %v", hex.EncodeToString(e.MessageID[:]))
}

// NewDocumentEvent is the new document event, signaling that
// we have received a new document from the PKI.
type NewDocumentEvent struct {
	Document *cpki.Document `cbor:document`
}

// String returns a string representation of a NewDocumentEvent.
func (e *NewDocumentEvent) String() string {
	return fmt.Sprintf("PKI Document for epoch %d", e.Document.Epoch)
}

// NewPKIDocumentEvent is the unix domain socket protocol message used
// by the daemon to tell the thin client about new PKI document events.
// The payload field contains a CBOR encoded PKI document, stripped of signatures.
type NewPKIDocumentEvent struct {
	Payload []byte `cbor:payload`
}

// String returns a string representation of a NewDocumentEvent.
func (e *NewPKIDocumentEvent) String() string {
	doc := &cpki.Document{}
	err := doc.Deserialize(e.Payload)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("PKI Document for epoch %d", doc.Epoch)
}