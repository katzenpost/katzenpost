// SPDX-FileCopyrightText: 2019, 2020, David Stainton <dawuud@riseup.net>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// contact.go - client
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
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/client"
	"github.com/katzenpost/core/crypto/rand"
	ratchet "github.com/katzenpost/doubleratchet"
	memspoolClient "github.com/katzenpost/memspool/client"
)

type contactExchange struct {
	SpoolWriteDescriptor *memspoolClient.SpoolWriteDescriptor
	SignedKeyExchange    *ratchet.SignedKeyExchange
}

// NewContactExchangeBytes returns serialized contact exchange information.
func NewContactExchangeBytes(spoolWriteDescriptor *memspoolClient.SpoolWriteDescriptor, signedKeyExchange *ratchet.SignedKeyExchange) ([]byte, error) {
	exchange := contactExchange{
		SpoolWriteDescriptor: spoolWriteDescriptor,
		SignedKeyExchange:    signedKeyExchange,
	}
	return cbor.Marshal(exchange)
}

func parseContactExchangeBytes(contactExchangeBytes []byte) (*contactExchange, error) {
	exchange := new(contactExchange)
	if err := cbor.Unmarshal(contactExchangeBytes, &exchange); err != nil {
		return nil, err
	}
	return exchange, nil
}

type serializedContact struct {
	ID                   uint64
	Nickname             string
	IsPending            bool
	KeyExchange          []byte
	PandaKeyExchange     []byte
	PandaResult          string
	Ratchet              []byte
	SpoolWriteDescriptor *memspoolClient.SpoolWriteDescriptor
}

// Contact is a communications contact that we have bidirectional
// communication with.
type Contact struct {
	// id is the local unique contact ID.
	id uint64

	// Nickname is also unique locally.
	Nickname string

	// IsPending is true if the key exchange has not been completed.
	IsPending bool

	// keyExchange is the serialised double ratchet key exchange we generated.
	keyExchange []byte

	// pandaKeyExchange is the serialised PANDA key exchange we generated.
	pandaKeyExchange []byte

	// pandaShutdownChan can be closed to trigger the shutdown of a PANDA
	// key exchange worker goroutine.
	pandaShutdownChan chan struct{}

	// pandaResult contains an error message if the PANDA exchange fails.
	pandaResult string

	// ratchet is the client's double ratchet for end to end encryption
	ratchet *ratchet.Ratchet

	// ratchetMutex is used to prevent a data race where the client
	// marshall's the ratchet and encrypts using the ratchet at the same time.
	ratchetMutex *sync.Mutex

	// spoolWriteDescriptor is a description of a remotely writable spool
	// which we must write to in order to send this contact a message.
	spoolWriteDescriptor *memspoolClient.SpoolWriteDescriptor
}

// NewContact creates a new Contact or returns an error.
func NewContact(nickname string, id uint64, spoolReadDescriptor *memspoolClient.SpoolReadDescriptor, session *client.Session) (*Contact, error) {
	ratchet, err := ratchet.InitRatchet(rand.Reader)
	if err != nil {
		return nil, err
	}
	signedKeyExchange, err := ratchet.CreateKeyExchange()
	if err != nil {
		return nil, err
	}
	spoolWriteDescriptor := spoolReadDescriptor.GetWriteDescriptor()
	exchange, err := NewContactExchangeBytes(spoolWriteDescriptor, signedKeyExchange)
	if err != nil {
		return nil, err
	}
	return &Contact{
		Nickname:          nickname,
		id:                id,
		IsPending:         true,
		ratchet:           ratchet,
		ratchetMutex:      new(sync.Mutex),
		keyExchange:       exchange,
		pandaShutdownChan: make(chan struct{}),
	}, nil
}

// ID returns the Contact ID.
func (c *Contact) ID() uint64 {
	return c.id
}

// MarshalBinary does what you expect and returns
// a serialized Contact.
func (c *Contact) MarshalBinary() ([]byte, error) {
	ratchetBlob, err := c.ratchet.MarshalBinary()
	if err != nil {
		return nil, err
	}
	s := &serializedContact{
		ID:                   c.id,
		Nickname:             c.Nickname,
		IsPending:            c.IsPending,
		KeyExchange:          c.keyExchange,
		PandaKeyExchange:     c.pandaKeyExchange,
		PandaResult:          c.pandaResult,
		Ratchet:              ratchetBlob,
		SpoolWriteDescriptor: c.spoolWriteDescriptor,
	}
	return cbor.Marshal(s)
}

// UnmarshalBinary does what you expect and initializes
// the given Contact with deserialized Contact fields
// from the given binary blob.
func (c *Contact) UnmarshalBinary(data []byte) error {
	r, err := ratchet.InitRatchet(rand.Reader)
	if err != nil {
		return err
	}

	s := new(serializedContact)
	if err = cbor.Unmarshal(data, &s); err != nil {
		return err
	}

	err = r.UnmarshalBinary(s.Ratchet)
	if err != nil {
		return err
	}

	c.id = s.ID
	c.Nickname = s.Nickname
	c.IsPending = s.IsPending
	c.keyExchange = s.KeyExchange
	c.pandaKeyExchange = s.PandaKeyExchange
	c.pandaResult = s.PandaResult
	c.ratchet = r
	c.spoolWriteDescriptor = s.SpoolWriteDescriptor

	return nil
}

func (c *Contact) Destroy() {
	ratchet.DestroyRatchet(c.ratchet)
}
