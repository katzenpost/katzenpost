// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only
package client2

import (
	"time"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/katzenpost/client2/thin"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

const (
	// MessageIDLength is the length of a message ID in bytes.
	MessageIDLength = 16

	// RoundTripTimeSlop is the slop added to the expected packet
	// round trip timeout threshold.
	RoundTripTimeSlop = (60 * time.Second)
)

// ARQState represents the state of an ARQ message in the stop-and-wait protocol.
type ARQState uint8

const (
	// ARQStateWaitingForACK is the initial state when a query is sent.
	// The client is waiting for an ACK from the courier.
	ARQStateWaitingForACK ARQState = 0

	// ARQStateACKReceived indicates that an ACK has been received from the courier.
	// For read queries, the client now needs to send another SURB to receive the payload.
	// For write queries, this is the terminal state.
	ARQStateACKReceived ARQState = 1

	// ARQStatePayloadReceived indicates that the payload has been received.
	// This is the terminal state for read queries.
	ARQStatePayloadReceived ARQState = 2
)

// ARQMessage is used by ARQ for automatic retransmission of Pigeonhole messages.
// It retries forever until cancelled via CancelResendingEncryptedMessage or successful.
type ARQMessage struct {
	// AppID identifies the application sending/receiving the message/reply.
	AppID *[AppIDLength]byte

	// QueryID is used for correlating replies with the original request.
	QueryID *[thin.QueryIDLength]byte

	// EnvelopeHash is the persistent identifier for this message.
	// Used to cancel resending via CancelResendingEncryptedMessage.
	EnvelopeHash *[32]byte

	// DestinationIdHash is 32 byte hash of the destination Courier's identity public key.
	DestinationIdHash *[32]byte

	// RecipientQueueID is the Courier queue identity.
	RecipientQueueID []byte

	// Payload is the MessageCiphertext (CourierQuery bytes) to send.
	Payload []byte

	// SURBID is the current SURB identifier.
	SURBID *[sConstants.SURBIDLength]byte

	// SURBDecryptionKeys is the SURB decryption keys for the current send.
	SURBDecryptionKeys []byte

	// Retransmissions counts the number of times this has been resent (for logging).
	Retransmissions uint32

	// SentAt contains the time the message was last sent.
	SentAt time.Time

	// ReplyETA is the expected round trip time to receive a response.
	ReplyETA time.Duration

	// EnvelopeDescriptor contains the key material to decrypt replies.
	EnvelopeDescriptor []byte

	// ReplicaEpoch is the epoch in which the envelope was created.
	ReplicaEpoch uint64

	// IsRead indicates whether this is a read operation (true) or write (false).
	IsRead bool

	// State tracks the current state in the stop-and-wait ARQ protocol.
	State ARQState

	// ReadCap is the read capability for BACAP decryption (only for read operations).
	ReadCap *bacap.ReadCap

	// NextMessageIndex is the message index for BACAP decryption (only for read operations).
	NextMessageIndex []byte
}
