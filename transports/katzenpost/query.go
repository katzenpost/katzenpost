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
	"fmt"

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
func (k *Transport) Query(command commands.Command) (commands.Command, error) {
	reply, err := k.Session.BlockingSendUnreliableMessage(k.Recipient, k.Provider, command.ToBytes())
	if err != nil {
		return nil, err
	}
	replyLen := binary.BigEndian.Uint32(reply[:4])
	cmd, err := commands.FromBytes(reply[4 : 4+replyLen])
	if err != nil {
		return nil, fmt.Errorf("Katzenpost Transport Query failure, reply len %d, %s", len(reply), err.Error())
	}
	return cmd, nil
}
