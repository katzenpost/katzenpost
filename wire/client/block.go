// block.go - Mixnet client using Noise based wire protocol.
// Copyright (C) 2017  David Anthony Stainton
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

// Package client provides the Katzenpost client side.
package client

import (
	"encoding/binary"
	"io"

	"github.com/katzenpost/noise"
)

const (
	blockOverhead   = 22
	messageIdLength = 16
	BlockLength     = 600 // XXX yawning: fix me
)

type Block struct {
	messageId   [messageIdLength]byte
	totalBlocks uint16
	blockId     uint16
	blockLength uint16
	block       []byte
	padding     []byte
}

func (b *Block) toBytes() []byte {
	out := make([]byte, blockOverhead+BlockLength)
	copy(out, b.messageId[:])
	binary.BigEndian.PutUint16(out[messageIdLength:], b.totalBlocks)
	binary.BigEndian.PutUint16(out[messageIdLength+2:], b.blockId)
	binary.BigEndian.PutUint16(out[messageIdLength+4:], b.blockLength) // XXX do something with length?
	copy(out[messageIdLength+6:], b.block)
	copy(out[messageIdLength+6+BlockLength:], b.padding)
	return out
}

func FromBytes(raw []byte) *Block {
	b := Block{}
	copy(b.messageId[:], raw[:messageIdLength])
	b.totalBlocks = binary.BigEndian.Uint16(raw[messageIdLength : messageIdLength+2])
	b.blockId = binary.BigEndian.Uint16(raw[messageIdLength+2 : messageIdLength+4])
	b.blockLength = binary.BigEndian.Uint16(raw[messageIdLength+4 : messageIdLength+6]) // XXX
	copy(b.block, raw[messageIdLength+6:messageIdLength+6+BlockLength])
	copy(b.padding, raw[messageIdLength+6+BlockLength:])
	return &b
}

type BlockClient struct {
	longtermKeypair noise.DHKey
	cipherSuite     noise.CipherSuite
	random          io.Reader
}

func NewBlockClient(LongtermX25519PublicKey, LongtermX25519PrivateKey *[32]byte, random io.Reader) *BlockClient {
	keypair := noise.DHKey{
		Private: LongtermX25519PrivateKey[:],
		Public:  LongtermX25519PublicKey[:],
	}
	blockClient := BlockClient{
		random:          random,
		longtermKeypair: keypair,
		cipherSuite:     noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b),
	}
	return &blockClient
}

func (c *BlockClient) EncryptBlock(peerPublicKey [32]byte, b *Block) []byte {
	handshakeState := noise.NewHandshakeState(noise.Config{
		CipherSuite:   c.cipherSuite,
		Random:        c.random,
		Pattern:       noise.HandshakeX,
		Initiator:     true,
		StaticKeypair: c.longtermKeypair,
		PeerStatic:    peerPublicKey[:],
	})
	plaintext := b.toBytes()
	ciphertext, _, _ := handshakeState.WriteMessage(nil, plaintext)
	return ciphertext
}

func (c *BlockClient) DecryptBlock(ciphertext []byte) (*Block, error) {
	handshakeState := noise.NewHandshakeState(noise.Config{
		CipherSuite:   c.cipherSuite,
		Random:        c.random,
		Pattern:       noise.HandshakeX,
		Initiator:     false,
		StaticKeypair: c.longtermKeypair,
	})

	plaintext, _, _, err := handshakeState.ReadMessage(nil, ciphertext)
	if err != nil {
		return nil, err
	}
	return FromBytes(plaintext), nil
}
