// client.go - client related structures
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

package client

import (
	"github.com/katzenpost/katzenpost/client2"
	"github.com/katzenpost/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/memspool/common"
)

// SpoolWriteDescriptor describes a remotely writable spool.
type SpoolWriteDescriptor struct {
	// ID is the identity of the described spool.
	ID [common.SpoolIDSize]byte

	// Receiver is the responding service name of the SURB based spool service.
	Receiver []byte

	// Provider is the name of the Provider hosting the spool.
	Provider *[32]byte
}

// SpoolReadDescriptor describes a remotely readable spool.
type SpoolReadDescriptor struct {
	// PrivateKey is the key material required for reading the described spool.
	PrivateKey *eddsa.PrivateKey

	// ID is the identity of the described spool.
	ID [common.SpoolIDSize]byte

	// Receiver is the responding service name of the SURB based spool service.
	Receiver []byte

	// Provider is the name of the Provider hosting the spool.
	Provider *[32]byte

	// ReadOffset is the number of messages to offset the next read from this
	// described spool.
	ReadOffset uint32
}

// IncrementOffset increments the ReadOffset
func (r *SpoolReadDescriptor) IncrementOffset() {
	r.ReadOffset += 1
}

// GetWriteDescriptor returns a SpoolWriteDescriptor which can
// used write to the given spool.
func (r *SpoolReadDescriptor) GetWriteDescriptor() *SpoolWriteDescriptor {
	return &SpoolWriteDescriptor{
		ID:       r.ID,
		Receiver: r.Receiver,
		Provider: r.Provider,
	}
}

// NewSpoolReadDescriptor blocks until the remote spool is created
// or the round trip timeout is reached.
func NewSpoolReadDescriptor(receiver []byte, provider *[32]byte, session *client2.ThinClient) (*SpoolReadDescriptor, error) {
	privateKey, err := eddsa.NewKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}
	createCmd, err := common.CreateSpool(privateKey)
	if err != nil {
		return nil, err
	}

	// create a kaetzchen Request
	id := session.NewMessageID()
	reply, err := session.BlockingSendReliableMessage(id, createCmd, provider, receiver)
	if err != nil {
		return nil, err
	}
	spoolResponse := &common.SpoolResponse{}
	err = spoolResponse.Unmarshal(reply)
	if err != nil {
		return nil, err
	}
	if !spoolResponse.IsOK() {
		return nil, spoolResponse.StatusAsError()
	}
	return &SpoolReadDescriptor{
		PrivateKey: privateKey,
		ID:         spoolResponse.SpoolID,
		Receiver:   receiver,
		Provider:   provider,
		ReadOffset: 1,
	}, nil
}
