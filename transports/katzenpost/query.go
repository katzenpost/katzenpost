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
	"gopkg.in/op/go-logging.v1"
)

type KatzenpostTransport struct {
	log       *logging.Logger
	session   *client.Session
	recipient string
	provider  string
}

func (k *KatzenpostTransport) Query(command commands.Command, haltCh chan interface{}) (commands.Command, error) {
	rawQuery := command.ToBytes()
	reply, err := k.session.BlockingSendUnreliableMessage(k.recipient, k.provider, rawQuery)
	if err != nil {
		return nil, err
	}
	return commands.FromBytes(reply)
}
