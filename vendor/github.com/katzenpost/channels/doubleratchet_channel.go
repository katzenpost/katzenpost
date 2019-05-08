// doubleratchet_channel.go - Signal Double Ratchet based mixnet communications channel
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

package channels

import (
	"encoding/binary"
	"errors"

	"github.com/katzenpost/core/crypto/rand"
	ratchet "github.com/katzenpost/doubleratchet"
	"github.com/katzenpost/memspool/client"
	"github.com/ugorji/go/codec"
)

const (
	// DoubleRatchetPayloadLength is the length of the payload encrypted by the ratchet.
	DoubleRatchetPayloadLength = SpoolPayloadLength - ratchet.DoubleRatchetOverhead
)

// UnreliableDoubleRatchetChannelExchange is exchanged between endpoints
// to establish a bidirectional channel, the UnreliableDoubleRatchetChannel.
type UnreliableDoubleRatchetChannelExchange struct {
	SpoolWriter       *UnreliableSpoolWriterChannel
	SignedKeyExchange *ratchet.SignedKeyExchange
}

// UnreliableDoubleRatchetChannel is an unreliable channel which encrypts using the double ratchet.
type UnreliableDoubleRatchetChannel struct {
	SpoolCh *UnreliableSpoolChannel
	Ratchet *ratchet.Ratchet
}

// LoadUnreliableDoubleRatchetChannel loads the channel given the saved blob and a SpoolService interface.
func LoadUnreliableDoubleRatchetChannel(data []byte, spoolService client.SpoolService) (*UnreliableDoubleRatchetChannel, error) {
	var err error
	s := new(UnreliableDoubleRatchetChannel)
	s.Ratchet, err = ratchet.New(rand.Reader)
	if err != nil {
		return nil, err
	}
	err = codec.NewDecoderBytes(data, cborHandle).Decode(s)
	if err != nil {
		return nil, err
	}
	s.SpoolCh.SetSpoolService(spoolService)
	return s, nil
}

// NewUnreliableDoubleRatchetChannel creates a new UnreliableDoubleRatchetChannel.
func NewUnreliableDoubleRatchetChannel(spoolCh *UnreliableSpoolChannel) (*UnreliableDoubleRatchetChannel, error) {
	ratchet, err := ratchet.New(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &UnreliableDoubleRatchetChannel{
		SpoolCh: spoolCh,
		Ratchet: ratchet,
	}, nil
}

// ChannelExchange returns a serialized UnreliableDoubleRatchetChannelExchange
// which is needed to connect channel endpoints.
func (r *UnreliableDoubleRatchetChannel) ChannelExchange() ([]byte, error) {
	signedKeyExchange, err := r.Ratchet.CreateKeyExchange()
	if err != nil {
		return nil, err
	}
	exchange := UnreliableDoubleRatchetChannelExchange{
		SpoolWriter:       r.SpoolCh.GetSpoolWriter(),
		SignedKeyExchange: signedKeyExchange,
	}
	var serialized []byte
	err = codec.NewEncoderBytes(&serialized, cborHandle).Encode(exchange)
	if err != nil {
		return nil, err
	}
	return serialized, nil
}

// ProcessKeyExchange processes the given signed key exchange.
func (r *UnreliableDoubleRatchetChannel) ProcessKeyExchange(kx *ratchet.SignedKeyExchange) error {
	return r.Ratchet.ProcessKeyExchange(kx)
}

// KeyExchange returns a signed key exchange or an error.
func (r *UnreliableDoubleRatchetChannel) KeyExchange() (*ratchet.SignedKeyExchange, error) {
	return r.Ratchet.CreateKeyExchange()
}

// ProcessChannelExchange consumes a serialized UnreliableDoubleRatchetChannelExchange
// and uses it to connection spool channels and ratchet channels so that our
// UnreliableDoubleRatchetChannel is fully connected.
func (r *UnreliableDoubleRatchetChannel) ProcessChannelExchange(cborExchange []byte) error {
	exchange := new(UnreliableDoubleRatchetChannelExchange)
	err := codec.NewDecoderBytes(cborExchange, cborHandle).Decode(exchange)
	if err != nil {
		return err
	}
	err = r.SpoolCh.WithRemoteWriter(exchange.SpoolWriter)
	if err != nil {
		return err
	}
	err = r.Ratchet.ProcessKeyExchange(exchange.SignedKeyExchange)
	if err != nil {
		return err
	}
	return nil
}

// Write writes a message, encrypting it with the double ratchet and
// sending the ciphertext to the remote spool.
func (r *UnreliableDoubleRatchetChannel) Write(message []byte) error {
	if r.SpoolCh == nil {
		panic("spool channel must not be nil")
	}
	if len(message) > DoubleRatchetPayloadLength {
		return errors.New("exceeds payload maximum")
	}
	payload := [DoubleRatchetPayloadLength]byte{}
	binary.BigEndian.PutUint32(payload[:4], uint32(len(message)))
	copy(payload[4:], message)
	ciphertext := r.Ratchet.Encrypt(nil, payload[:])
	return r.SpoolCh.Write(ciphertext[:])
}

// Read reads ciphertext from a remote spool and decypts
// it with the double ratchet.
func (r *UnreliableDoubleRatchetChannel) Read() ([]byte, error) {
	ciphertext, err := r.SpoolCh.Read()
	if err != nil {
		return nil, err
	}
	plaintext, err := r.Ratchet.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}
	payloadLen := binary.BigEndian.Uint32(plaintext[:4])
	return plaintext[4 : 4+payloadLen], nil
}

// Save returns the serialization of this channel suitable to
// be used to "load" this channel and make use of it in the future.
func (r *UnreliableDoubleRatchetChannel) Save() ([]byte, error) {
	var serialized []byte
	enc := codec.NewEncoderBytes(&serialized, cborHandle)
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return serialized, nil
}
