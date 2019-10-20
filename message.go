// message.go - mixnet client internal message type
// Copyright (C) 2018, 2019  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package client

import (
	"time"

	cConstants "github.com/katzenpost/client/constants"
	sConstants "github.com/katzenpost/core/sphinx/constants"
)

// Message is a message reference which is used to match future
// received SURB replies.
type Message struct {
	// ID is the message identifier
	ID *[cConstants.MessageIDLength]byte

	// Recipient is the message recipient
	Recipient string

	// Provider is the recipient Provider
	Provider string

	// Payload is the message payload
	Payload []byte

	// SentAt contains the time the message was sent.
	SentAt time.Time

	// ReplyETA is the expected round trip time to receive a response.
	ReplyETA time.Duration

	// IsBlocking indicates whether or not the client is blocking on the
	// sending of the query and the receiving of it's reply.
	IsBlocking bool

	// SURBID is the SURB identifier.
	SURBID *[sConstants.SURBIDLength]byte

	// Key is the SURB decryption keys
	Key []byte

	// Reply is the SURB reply
	Reply []byte

	// WithSURB specified if a SURB should be bundled with the forward payload.
	WithSURB bool

	// Specifies if this message is a decoy.
	IsDecoy bool

	// Priority controls the dwell time in the current AQM.
	QueuePriority uint64
}

func (m *Message) Priority() uint64 {
	return m.QueuePriority
}
