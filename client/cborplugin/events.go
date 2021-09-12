// events.go - cbor plugin events
// Copyright (C) 2021  David Stainton.
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

package cborplugin

import (
	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/katzenpost/client/events"
	"github.com/katzenpost/katzenpost/core/cborplugin"
)

type Event struct {
	ConnectionStatusEvent     *events.ConnectionStatusEvent
	MessageReplyEvent         *events.MessageReplyEvent
	MessageSentEvent          *events.MessageSentEvent
	MessageIDGarbageCollected *events.MessageIDGarbageCollected
	NewDocumentEvent          *events.NewDocumentEvent
}

func (c *Event) Marshal() ([]byte, error) {
	return cbor.Marshal(c)
}

func (c *Event) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, c)
}

type EventBuilder struct{}

func (p *EventBuilder) Build() cborplugin.Command {
	return new(Event)
}
