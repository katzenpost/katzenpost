// query.go - Reunion client query transport for Katzenpost mix network.
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

// Package katzenpost provides the client ACN transport for Reunion
// DB queries on a katzenpost decryption mix network.
package katzenpost

import (
	"github.com/katzenpost/client"
	"github.com/katzenpost/reunion/commands"
)

// Transport is used by Reunion protocol
// clients to send queries to the Reunion DB service.
type Transport struct {
	// Session is a client Session which
	// can be used to send mixnet messages.
	Session *client.Session
	// Recipient is the destination service.
	Recipient string
	// Provider is the destination Provider.
	Provider string
}

// Query sends the command to the destination Reunion DB service
// over a Katzenpost mix network.
func (k *Transport) Query(command commands.Command, haltCh chan interface{}) (commands.Command, error) {
	rawQuery := command.ToBytes()
	reply, err := k.Session.BlockingSendUnreliableMessage(k.Recipient, k.Provider, rawQuery)
	if err != nil {
		return nil, err
	}
	return commands.FromBytes(reply)
}
