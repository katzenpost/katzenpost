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
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"

	cConstants "github.com/katzenpost/katzenpost/client/constants"
	ratchet "github.com/katzenpost/katzenpost/doubleratchet"
	memspoolClient "github.com/katzenpost/katzenpost/memspool/client"
)

type contactExchange struct {
	SpoolWriteDescriptor *memspoolClient.SpoolWriteDescriptor
	KeyExchange          []byte
}

// NewContactExchangeBytes returns serialized contact exchange information.
func NewContactExchangeBytes(spoolWriteDescriptor *memspoolClient.SpoolWriteDescriptor, keyExchange []byte) ([]byte, error) {
	exchange := contactExchange{
		SpoolWriteDescriptor: spoolWriteDescriptor,
		KeyExchange:          keyExchange,
	}
	return cbor.Marshal(exchange)
}

func parseContactExchangeBytes(contactExchangeBytes []byte) (*contactExchange, error) {
	exchange := new(contactExchange)
	if _, err := cbor.UnmarshalFirst(contactExchangeBytes, &exchange); err != nil {
		return nil, err
	}
	return exchange, nil
}

type serializedContact struct {
	NIKEScheme           string
	ID                   uint64
	Nickname             string
	IsPending            bool
	KeyExchange          []byte
	PandaKeyExchange     []byte
	PandaResult          string
	ReunionKeyExchange   map[uint64]boundExchange
	ReunionResult        map[uint64]string
	Ratchet              []byte
	Outbound             *Queue
	SharedSecret         []byte
	SpoolWriteDescriptor *memspoolClient.SpoolWriteDescriptor
	MessageExpiration    time.Duration
}

type boundExchange struct {
	serialized []byte
	recipient  string
	provider   string
}

// Contact is a communications contact that we have bidirectional
// communication with.
type Contact struct {
	nikeScheme nike.Scheme

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
	pandaShutdownChan chan interface{}

	// reunionShutdownChans can be closed to trigger the shutodwn of a Reunion
	// key exchange worker goroutine.
	reunionShutdownChan chan struct{}

	// pandaResult contains an error message if the PANDA exchange fails.
	pandaResult string

	// reunionKeyExchange is the serialized Reunion exchange state.
	reunionKeyExchange map[uint64]boundExchange

	// reunionResult contains an error message if the Reunion exchange fails.
	reunionResult map[uint64]string

	// ratchet is the client's double ratchet for end to end encryption
	ratchet *ratchet.Ratchet

	// ratchetMutex is used to prevent a data race where the client
	// marshall's the ratchet and encrypts using the ratchet at the same time.
	ratchetMutex *sync.Mutex

	// spoolWriteDescriptor is a description of a remotely writable spool
	// which we must write to in order to send this contact a message.
	spoolWriteDescriptor *memspoolClient.SpoolWriteDescriptor

	// sharedSecret is the passphrase used to add the contact.
	sharedSecret []byte

	// outbound is a queue of messages waiting to be sent for this client
	// messages must be acknowledged in order before another message will
	// be sent
	outbound *Queue
	ackID    [cConstants.MessageIDLength]byte

	LastMessage *Message

	// messageExpiration is the duration after which conversation history is cleared
	messageExpiration time.Duration
}

// NewContact creates a new Contact or returns an error.
func NewContact(nickname string, id uint64, secret []byte, nikeSchemeName string) (*Contact, error) {
	nikeScheme := schemes.ByName(nikeSchemeName)
	ratchet, err := ratchet.InitRatchet(rand.Reader, nikeScheme)
	if err != nil {
		return nil, err
	}
	return &Contact{
		nikeScheme:          nikeScheme,
		Nickname:            nickname,
		id:                  id,
		IsPending:           true,
		ratchet:             ratchet,
		ratchetMutex:        new(sync.Mutex),
		sharedSecret:        secret,
		pandaShutdownChan:   make(chan interface{}),
		reunionShutdownChan: make(chan struct{}),
		outbound:            new(Queue),
		messageExpiration:   MessageExpirationDuration,
	}, nil
}

// ID returns the Contact ID.
func (c *Contact) ID() uint64 {
	return c.id
}

// MarshalBinary does what you expect and returns
// a serialized Contact.
func (c *Contact) MarshalBinary() ([]byte, error) {
	// obtain the ratchet mutex first...
	c.ratchetMutex.Lock()
	ratchetBlob, err := c.ratchet.Save()
	c.ratchetMutex.Unlock()
	if err != nil {
		return nil, err
	}
	s := &serializedContact{
		NIKEScheme:           c.nikeScheme.Name(),
		ID:                   c.id,
		Nickname:             c.Nickname,
		IsPending:            c.IsPending,
		KeyExchange:          c.keyExchange,
		PandaKeyExchange:     c.pandaKeyExchange,
		PandaResult:          c.pandaResult,
		ReunionKeyExchange:   c.reunionKeyExchange,
		ReunionResult:        c.reunionResult,
		Ratchet:              ratchetBlob,
		SharedSecret:         c.sharedSecret,
		SpoolWriteDescriptor: c.spoolWriteDescriptor,
		Outbound:             c.outbound,
		MessageExpiration:    c.messageExpiration,
	}
	return cbor.Marshal(s)
}

// UnmarshalBinary does what you expect and initializes
// the given Contact with deserialized Contact fields
// from the given binary blob.
func (c *Contact) UnmarshalBinary(data []byte) error {
	s := new(serializedContact)
	if _, err := cbor.UnmarshalFirst(data, &s); err != nil {
		return err
	}

	r, err := ratchet.NewRatchetFromBytes(rand.Reader, s.Ratchet, c.nikeScheme)
	if err != nil {
		return err
	}

	c.nikeScheme = schemes.ByName(s.NIKEScheme)
	c.id = s.ID
	c.Nickname = s.Nickname
	c.IsPending = s.IsPending
	c.keyExchange = s.KeyExchange
	c.pandaKeyExchange = s.PandaKeyExchange
	c.pandaResult = s.PandaResult
	c.reunionKeyExchange = s.ReunionKeyExchange
	c.reunionResult = s.ReunionResult
	c.ratchetMutex = new(sync.Mutex)
	c.ratchet = r
	c.sharedSecret = s.SharedSecret
	c.spoolWriteDescriptor = s.SpoolWriteDescriptor
	c.outbound = s.Outbound
	c.messageExpiration = s.MessageExpiration
	if c.IsPending {
		c.pandaShutdownChan = make(chan interface{})
		c.reunionShutdownChan = make(chan struct{})
	}
	return nil
}

func (c *Contact) Destroy() {
	c.ratchetMutex.Lock()
	ratchet.DestroyRatchet(c.ratchet)
	c.ratchetMutex.Unlock()
}

func (c *Contact) haltKeyExchanges() {
	if c.IsPending {
		if c.pandaShutdownChan != nil {
			close(c.pandaShutdownChan)
			c.pandaShutdownChan = nil
		}
		if c.reunionShutdownChan != nil {
			close(c.reunionShutdownChan)
			c.reunionShutdownChan = nil
		}
	}
}
