// event.go - mixnet client session events
// Copyright (C) 2018, 2019  Yawning Angel and David Stainton.
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

package session

import (
	"encoding/hex"
	"fmt"

	cConstants "github.com/katzenpost/client/constants"
)

// Event is the generic event sent over the event listener channel.
type Event interface {
	// String returns a string representation of the Event.
	String() string
}

// ConnectionStatusEvent is the event sent when an account's connection status
// changes.
type ConnectionStatusEvent struct {
	// IsConnected is true iff the account is connected to the provider.
	IsConnected bool

	// Err is the error encountered when connecting or by the connection if any.
	Err error
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
	MessageID *[cConstants.MessageIDLength]byte

	// Payload is the reply payload if any.
	Payload []byte

	// Err is the error encountered when servicing the request if any.
	Err error
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
	MessageID *[cConstants.MessageIDLength]byte

	// Err is the error encountered when sending the message if any.
	Err error
}

// String returns a string representation of a MessageSentEvent.
func (e *MessageSentEvent) String() string {
	if e.Err != nil {
		return fmt.Sprintf("MessageSent: %v failed: %v", hex.EncodeToString(e.MessageID[:]), e.Err)
	}
	return fmt.Sprintf("MessageSent: %v", hex.EncodeToString(e.MessageID[:]))
}
