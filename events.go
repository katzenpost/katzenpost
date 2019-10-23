// events.go - catshadow events
// Copyright (C) 2019  David Stainton.
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

package catshadow

import (
	"time"

	"github.com/katzenpost/catshadow/constants"
)

// KeyExchangeCompletedEvent is an event signaling the completion
// of a key exchange or failure if Err is non-nil.
type KeyExchangeCompletedEvent struct {
	// Nickname is the nickname of the contact with whom our key
	// exchange has been completed.
	Nickname string
	// Err is a key exchange error or is set to nil on success.
	Err error
}

// MessageSentEvent is an event signaling that the message
// was sent.
type MessageSentEvent struct {
	// Nickname is the nickname of the recipient of our delivered message.
	Nickname string

	// MessageID is the key in the conversation map referencing a specific message.
	MessageID [constants.MessageIDLen]byte
}

// MessageDeliveredEvent is an event signaling that the message
// has been delivered.
type MessageDeliveredEvent struct {
	// Nickname is the nickname of the recipient of our delivered message.
	Nickname string

	// MessageID is the key in the conversation map referencing a specific message.
	MessageID [constants.MessageIDLen]byte
}

// MessageReceivedEvent is the event signaling that a message was received.
type MessageReceivedEvent struct {
	// Nickname is the nickname from whom we received a message.
	Nickname string
	// Message is the message content which was received.
	Message []byte
	// Timestamp is the time the message was received.
	Timestamp time.Time
}
