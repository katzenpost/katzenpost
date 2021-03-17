// SPDX-FileCopyrightText: 2019, David Stainton <dawuud@riseup.net>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// events.go - catshadow events
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

// MessageNotSentEvent is an event signalling that the message
// was not sent.
type MessageNotSentEvent struct {
	// Nickname is the nickname of the recipient of our delivered message.
	Nickname string

	// MessageID is the key in the conversation map referencing a specific message.
	MessageID MessageID

	// Err is an error with reason for failure
	Err error
}

// MessageSentEvent is an event signaling that the message
// was sent.
type MessageSentEvent struct {
	// Nickname is the nickname of the recipient of our delivered message.
	Nickname string

	// MessageID is the key in the conversation map referencing a specific message.
	MessageID MessageID
}

// MessageDeliveredEvent is an event signaling that the message
// has been delivered to the remote spool.
type MessageDeliveredEvent struct {
	// Nickname is the nickname of the recipient of our delivered message.
	Nickname string

	// MessageID is the key in the conversation map referencing a specific message.
	MessageID MessageID
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
