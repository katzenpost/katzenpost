// noise_channel.go - Noise based mixnet communications channel
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
	"errors"
	"fmt"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/memspool/client"
	"github.com/katzenpost/noise"
	"github.com/ugorji/go/codec"
)

const (
	// NoiseOverhead is amount of bytes overhead from the noise encryption.
	NoiseOverhead = keyLength + macLength + keyLength + macLength // e, es, s, ss
	keyLength     = 32
	macLength     = 16

	// NoisePayloadLength is the length of the noise payload.
	NoisePayloadLength = SpoolPayloadLength - NoiseOverhead
)

// NoiseWriterDescriptor contains the information necessary
// to write to a remote spool.
type NoiseWriterDescriptor struct {
	SpoolWriterChan      *UnreliableSpoolWriterChannel
	RemoteNoisePublicKey *ecdh.PublicKey
}

// UnreliableNoiseChannel is an unreliable channel which encrypts using
// the Noise X one-way pattern.
type UnreliableNoiseChannel struct {
	spoolService client.SpoolService

	SpoolWriterChan      *UnreliableSpoolWriterChannel
	RemoteNoisePublicKey *ecdh.PublicKey

	SpoolReaderChan *UnreliableSpoolReaderChannel
	NoisePrivateKey *ecdh.PrivateKey
	ReadOffset      uint32
}

// NewUnreliableNoiseChannel creates and returns a new UnreliableNoiseChannel or an error.
func NewUnreliableNoiseChannel(spoolReceiver, spoolProvider string, spool client.SpoolService) (*UnreliableNoiseChannel, error) {
	noisePrivateKey, err := ecdh.NewKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}
	spoolReader, err := NewUnreliableSpoolReaderChannel(spoolReceiver, spoolProvider, spool)
	if err != nil {
		return nil, err
	}
	return &UnreliableNoiseChannel{
		spoolService:         spool,
		SpoolWriterChan:      nil,
		RemoteNoisePublicKey: nil,
		SpoolReaderChan:      spoolReader,
		NoisePrivateKey:      noisePrivateKey,
		ReadOffset:           1,
	}, nil
}

// WithRemoteWriter allows this channel to write to a remote spool.
func (n *UnreliableNoiseChannel) WithRemoteWriter(writerDesc *NoiseWriterDescriptor) {
	if writerDesc.SpoolWriterChan == nil || writerDesc.RemoteNoisePublicKey == nil {
		panic("writer channel must not be nil")
	}
	n.SpoolWriterChan = writerDesc.SpoolWriterChan
	n.RemoteNoisePublicKey = writerDesc.RemoteNoisePublicKey
}

// GetRemoteWriter returns a NoiseWriterDescriptor which describes how
// a writer can write to the spool we are reading.
func (n *UnreliableNoiseChannel) GetRemoteWriter() *NoiseWriterDescriptor {
	return &NoiseWriterDescriptor{
		SpoolWriterChan:      n.SpoolReaderChan.GetSpoolWriter(),
		RemoteNoisePublicKey: n.NoisePrivateKey.PublicKey(),
	}
}

// Read reads from a remote spool and decrypts.
func (n *UnreliableNoiseChannel) Read() ([]byte, error) {
	ciphertext, err := n.SpoolReaderChan.Read(n.spoolService)
	if err != nil {
		return nil, err
	}

	// Decrypt the ciphertext into a plaintext.
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	recipientDH := noise.DHKey{
		Private: n.NoisePrivateKey.Bytes(),
		Public:  n.NoisePrivateKey.PublicKey().Bytes(),
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeX,
		Initiator:     false,
		StaticKeypair: recipientDH,
		PeerStatic:    nil,
	})
	if err != nil {
		return nil, err
	}
	plaintext, _, _, err := hs.ReadMessage(nil, ciphertext)
	if err != nil {
		return nil, err
	}

	// Check that the sender's static Noise X key is the key we expected.
	senderPk := new(ecdh.PublicKey)
	if err = senderPk.FromBytes(hs.PeerStatic()); err != nil {
		panic("BUG: block: Failed to de-serialize peer static key: " + err.Error())
	}
	if !n.RemoteNoisePublicKey.Equal(senderPk) {
		return nil, errors.New("wtf, wrong partner Noise X key")
	}

	return plaintext, nil
}

// Write encrypts and write to a remote spool.
func (n *UnreliableNoiseChannel) Write(message []byte) error {
	if len(message) > NoisePayloadLength {
		return fmt.Errorf("exceeds noise channel payload maximum: %d > %d", len(message), NoisePayloadLength)
		//return errors.New("exceeds noise channel payload maximum")
	}

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	senderDH := noise.DHKey{
		Private: n.NoisePrivateKey.Bytes(),
		Public:  n.NoisePrivateKey.PublicKey().Bytes(),
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeX,
		Initiator:     true,
		StaticKeypair: senderDH,
		PeerStatic:    n.RemoteNoisePublicKey.Bytes(),
	})
	if err != nil {
		return err
	}
	ciphertext, _, _, err := hs.WriteMessage(nil, message)
	if err != nil {
		return err
	}
	return n.SpoolWriterChan.Write(n.spoolService, ciphertext)
}

// SetSpoolService sets this channel's spoolService field.
func (n *UnreliableNoiseChannel) SetSpoolService(spoolService client.SpoolService) {
	n.spoolService = spoolService
}

// Save returns a serialized form of this channel suitable to be
// reloaded for later use.
func (n *UnreliableNoiseChannel) Save() ([]byte, error) {
	var serialized []byte
	enc := codec.NewEncoderBytes(&serialized, cborHandle)
	if err := enc.Encode(n); err != nil {
		return nil, err
	}
	return serialized, nil
}

// LoadUnreliableNoiseChannel loads a serialized channel and sets it's spoolService so that
// it may be used.
func LoadUnreliableNoiseChannel(data []byte, spoolService client.SpoolService) (*UnreliableNoiseChannel, error) {
	n := new(UnreliableNoiseChannel)
	err := codec.NewDecoderBytes(data, cborHandle).Decode(n)
	if err != nil {
		return nil, err
	}
	n.SetSpoolService(spoolService)
	return n, nil
}
