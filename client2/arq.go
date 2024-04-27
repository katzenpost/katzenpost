// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only
package client2

import (
	"time"

	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

const (
	// MessageIDLength is the length of a message ID in bytes.
	MessageIDLength = 16

	// RoundTripTimeSlop is the slop added to the expected packet
	// round trip timeout threshold.
	RoundTripTimeSlop = (2 * time.Minute) + (15 * time.Second)

	MaxRetransmissions = 3
)

// ARQMessage is used by ARQ.
type ARQMessage struct {

	// AppID identifies the application sending/receiving the message/reply.
	AppID *[AppIDLength]byte

	// MessageID is the unique message identifier
	MessageID *[MessageIDLength]byte

	// DestinationIdHash is 32 byte hash of the destination Provider's
	// identity public key.
	DestinationIdHash *[32]byte

	// RecipientQueueID is the queue identity which will receive the message.
	RecipientQueueID []byte

	// Payload is the message payload
	Payload []byte

	// SURBID is the SURB identifier.
	SURBID *[sConstants.SURBIDLength]byte

	// SURBDecryptionKeys is the SURB decryption keys
	SURBDecryptionKeys []byte

	// Retransmissions counts the number of times the message has been retransmitted.
	Retransmissions uint32

	// SentAt contains the time the message was sent.
	SentAt time.Time

	// ReplyETA is the expected round trip time to receive a response.
	ReplyETA time.Duration
}
