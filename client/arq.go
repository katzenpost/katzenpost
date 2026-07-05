// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only
package client

import (
	"time"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/katzenpost/client/thin"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

const (
	// MessageIDLength is the length of a message ID in bytes.
	MessageIDLength = 16

	// RoundTripTimeSlop is the slop added to the expected packet
	// round trip timeout threshold.
	RoundTripTimeSlop = (20 * time.Second)
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

// ARQAction represents the action to take after an ARQ state transition.
type ARQAction int

const (
	// ARQActionSendNewSURB means send a new SURB to continue the protocol.
	ARQActionSendNewSURB ARQAction = iota
	// ARQActionComplete means the operation completed successfully.
	ARQActionComplete
	// ARQActionHandlePayload means the payload reply should be processed.
	ARQActionHandlePayload
	// ARQActionError means the reply contained an error code.
	ARQActionError
	// ARQActionIgnore means the reply should be ignored (terminal state).
	ARQActionIgnore
)

// ARQTransitionResult is the output of the ARQ state machine transition.
type ARQTransitionResult struct {
	NewState     ARQState
	Action       ARQAction
	ShouldRemove bool
	ErrorCode    uint8
}

// computeARQStateTransition is the pure FSM logic for the pigeonhole ARQ protocol.
// It determines what action to take based on the current state, reply type, and flags.
func computeARQStateTransition(
	state ARQState,
	replyType uint8,
	errorCode uint8,
	isRead bool,
	noIdempotentBoxAlreadyExists bool,
) ARQTransitionResult {
	// Error in reply → remove from tracking, report error
	if errorCode != 0 {
		return ARQTransitionResult{
			NewState:     state,
			Action:       ARQActionError,
			ShouldRemove: true,
			ErrorCode:    errorCode,
		}
	}

	switch state {
	case ARQStateWaitingForACK:
		if replyType == 0 { // ReplyTypeACK
			// For default writes (idempotent), ACK is sufficient
			if !isRead && !noIdempotentBoxAlreadyExists {
				return ARQTransitionResult{
					NewState:     state,
					Action:       ARQActionComplete,
					ShouldRemove: true,
				}
			}
			// Reads and non-idempotent writes need a payload reply
			return ARQTransitionResult{
				NewState:     ARQStateACKReceived,
				Action:       ARQActionSendNewSURB,
				ShouldRemove: false,
			}
		}
		// Got payload while waiting for ACK — treat as both
		return ARQTransitionResult{
			NewState:     ARQStatePayloadReceived,
			Action:       ARQActionHandlePayload,
			ShouldRemove: false,
		}

	case ARQStateACKReceived:
		if replyType == 1 { // ReplyTypePayload
			return ARQTransitionResult{
				NewState:     ARQStatePayloadReceived,
				Action:       ARQActionHandlePayload,
				ShouldRemove: false,
			}
		}
		// Duplicate ACK — data not ready, keep polling
		return ARQTransitionResult{
			NewState:     ARQStateACKReceived,
			Action:       ARQActionSendNewSURB,
			ShouldRemove: false,
		}

	case ARQStatePayloadReceived:
		// Terminal state — ignore
		return ARQTransitionResult{
			NewState:     ARQStatePayloadReceived,
			Action:       ARQActionIgnore,
			ShouldRemove: false,
		}
	}

	// Unknown state — ignore
	return ARQTransitionResult{
		NewState:     state,
		Action:       ARQActionIgnore,
		ShouldRemove: false,
	}
}

// ARQMessageType distinguishes between different types of ARQ messages.
type ARQMessageType uint8

const (
	// ARQMessageTypeEnvelope is for encrypted read/write envelope operations.
	ARQMessageTypeEnvelope ARQMessageType = 0

	// ARQMessageTypeCopyCommand is for copy command operations.
	ARQMessageTypeCopyCommand ARQMessageType = 1
)

// ARQMessage is used by ARQ for automatic retransmission of Pigeonhole messages.
// It retries forever until cancelled via CancelResendingEncryptedMessage or successful.
type ARQMessage struct {
	// MessageType distinguishes between envelope operations and copy commands.
	// This determines how the reply is processed.
	MessageType ARQMessageType

	// AppID identifies the application sending/receiving the message/reply.
	AppID *[AppIDLength]byte

	// QueryID is used for correlating replies with the original request.
	QueryID *[thin.QueryIDLength]byte

	// EnvelopeHash is the persistent identifier for this message.
	// Used to cancel resending via CancelResendingEncryptedMessage.
	// For copy commands, this is a hash of the WriteCap.
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

	// IsRead indicates whether this is a read operation (true) or write (false).
	IsRead bool

	// State tracks the current state in the stop-and-wait ARQ protocol.
	State ARQState

	// ReadCap is the read capability for BACAP decryption (only for read operations).
	ReadCap *bacap.ReadCap

	// MessageBoxIndex is the current message box index being operated on (only for read operations).
	MessageBoxIndex []byte

	// NoRetryOnBoxIDNotFound disables automatic retries on BoxIDNotFound for read operations.
	// When true, BoxIDNotFound is returned immediately. When false (default), reads retry
	// up to 10 times to handle replication lag.
	NoRetryOnBoxIDNotFound bool

	// NoIdempotentBoxAlreadyExists disables treating BoxAlreadyExists as idempotent success
	// for write operations. When true, BoxAlreadyExists is returned as an error.
	// When false (default), BoxAlreadyExists is treated as success (the write already happened).
	NoIdempotentBoxAlreadyExists bool
}
