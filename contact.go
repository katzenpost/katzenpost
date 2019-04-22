// contact.go - client
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
	"github.com/katzenpost/channels"
	"github.com/katzenpost/client/session"
	"github.com/katzenpost/memspool/client"
	"github.com/katzenpost/memspool/common"
)

// Contact is a communications contact that we have bidirectional
// communication with.
type Contact struct {
	// id is the local unique contact ID.
	id uint64
	// nickname is also unique locally.
	nickname string
	// isPending is true if the key exchange has not been completed.
	isPending bool
	// keyExchange is the serialised double ratchet key exchange we generated.
	keyExchange []byte
	// pandaKeyExchange is the serialised PANDA key exchange we generated.
	pandaKeyExchange []byte
	// pandaShutdownChan can be closed to trigger the shutdown of a PANDA
	// key exchange worker goroutine.
	pandaShutdownChan chan struct{}
	// pandaResult contains an error message if the PANDA exchange fails.
	pandaResult string
	// channel is the bidirectional remote spool based communications
	// channel that is encrypted with the double ratchet.
	channel *channels.UnreliableDoubleRatchetChannel
}

// NewContact creates a new Contact or returns an error.
func NewContact(nickname string, id uint64, session *session.Session) (*Contact, error) {
	serviceDesc, err := session.GetService(common.SpoolServiceName)
	if err != nil {
		return nil, err
	}
	spoolService := client.New(session)
	spoolChan, err := channels.NewUnreliableSpoolChannel(serviceDesc.Name, serviceDesc.Provider, spoolService)
	if err != nil {
		return nil, err
	}
	ratchetChan, err := channels.NewUnreliableDoubleRatchetChannel(spoolChan)
	if err != nil {
		return nil, err
	}
	keyExchange, err := ratchetChan.ChannelExchange()
	if err != nil {
		return nil, err
	}
	return &Contact{
		nickname:          nickname,
		id:                id,
		isPending:         true,
		channel:           ratchetChan,
		keyExchange:       keyExchange,
		pandaShutdownChan: make(chan struct{}),
	}, nil
}

func (c *Contact) processKeyExchange(kxsBytes []byte) error {
	return c.channel.ProcessChannelExchange(kxsBytes)
}

// ID returns the Contact ID.
func (c *Contact) ID() uint64 {
	return c.id
}
