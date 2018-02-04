// block.go - End to End message block routines.
// Copyright (C) 2017  Yawning Angel.
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

// Package block provides routines for manipulating End to End blocks.
package block

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/utils"
	"github.com/katzenpost/noise"
)

const (
	// MessageIDLength is the length of a message ID in bytes.
	MessageIDLength = 16

	// BlockCiphertextLength is the length of a BlockCiphertext in bytes.
	BlockCiphertextLength = constants.UserForwardPayloadLength

	// BlockPayloadLength is the maximum user payload length in a Block.
	BlockPayloadLength = BlockCiphertextLength - (blockCiphertextOverhead + blockOverhead)

	blockCiphertextOverhead = keyLength + macLength + keyLength + macLength // e, es, s, ss
	blockOverhead           = MessageIDLength + 2 + 2 + 4
	blockLength             = blockOverhead + BlockPayloadLength
	keyLength               = 32
	macLength               = 16

	totalBlocksOffset = MessageIDLength
	blockIDOffset     = totalBlocksOffset + 2
	blockLengthOffset = blockIDOffset + 2
	payloadOffset     = blockLengthOffset + 4
)

// Block is a Katzenpost end to end Block (plaintext).
type Block struct {
	MessageID   [MessageIDLength]byte
	TotalBlocks uint16
	BlockID     uint16
	BlockLength uint32
	Payload     []byte
}

// ToBytes serializes a Block into bytes.
func (b *Block) ToBytes() ([]byte, error) {
	if b.BlockID >= b.TotalBlocks {
		return nil, fmt.Errorf("block: BlockID (%v) >= TotalBlocks (%v)", b.BlockID, b.TotalBlocks)
	}
	if len(b.Payload) > BlockPayloadLength {
		return nil, fmt.Errorf("block: payload oversized: %v", len(b.Payload))
	}
	if len(b.Payload) != int(b.BlockLength) {
		return nil, fmt.Errorf("block: payload length mismatch: %v (Expecting %v)", len(b.Payload), b.BlockLength)
	}

	buf := make([]byte, blockLength)
	copy(buf[0:], b.MessageID[:])
	binary.BigEndian.PutUint16(buf[totalBlocksOffset:], b.TotalBlocks)
	binary.BigEndian.PutUint16(buf[blockIDOffset:], b.BlockID)
	binary.BigEndian.PutUint32(buf[blockLengthOffset:], b.BlockLength)
	copy(buf[payloadOffset:], b.Payload)

	return buf, nil
}

// FromBytes deserializes bytes into the Block.
func (b *Block) FromBytes(buf []byte) error {
	if len(buf) != blockLength {
		return fmt.Errorf("block: invalid byte serialized length: %v (Expecting %v)", len(buf), blockLength)
	}

	copy(b.MessageID[:], buf[0:])
	b.TotalBlocks = binary.BigEndian.Uint16(buf[totalBlocksOffset:])
	b.BlockID = binary.BigEndian.Uint16(buf[blockIDOffset:])
	b.BlockLength = binary.BigEndian.Uint32(buf[blockLengthOffset:])

	// Sanity check the deserialized values.
	if b.BlockID >= b.TotalBlocks {
		return fmt.Errorf("block: BlockID (%v) >= TotalBlocks (%v)", b.BlockID, b.TotalBlocks)
	}
	if b.BlockLength > BlockPayloadLength {
		return fmt.Errorf("block: payload oversized: %v", len(b.Payload))
	}
	// XXX: Should this reject undersized non-terminal blocks?

	// Copy out the payload into a new buffer.
	if b.BlockLength != 0 {
		padOffset := payloadOffset + b.BlockLength
		if !utils.CtIsZero(buf[padOffset:]) {
			return fmt.Errorf("block: padding is non-zero filled")
		}
		b.Payload = make([]byte, b.BlockLength)
		copy(b.Payload, buf[payloadOffset:padOffset])
	}

	return nil
}

func bytesVectorFromMessage(msgID *[MessageIDLength]byte, msg []byte) ([][]byte, error) {
	totalBlocks := (len(msg) + (BlockPayloadLength - 1)) / BlockPayloadLength
	if totalBlocks > math.MaxUint16 {
		return nil, fmt.Errorf("block: message requires too many blocks: %v", totalBlocks)
	}

	// Special case for 0 length messages.
	if len(msg) == 0 {
		blk := &Block{
			TotalBlocks: 1,
			BlockID:     0,
			BlockLength: 0,
		}
		copy(blk.MessageID[:], msgID[:])
		b, _ := blk.ToBytes()
		return [][]byte{b}, nil
	}

	blocks := make([][]byte, 0, totalBlocks)
	blkID := uint16(0)
	for off, remaining := 0, len(msg); remaining > 0; {
		sz := BlockPayloadLength
		if sz > remaining {
			sz = remaining
		}

		blk := &Block{
			TotalBlocks: uint16(totalBlocks),
			BlockID:     blkID,
			BlockLength: uint32(sz),
			Payload:     make([]byte, sz),
		}
		copy(blk.MessageID[:], msgID[:])
		copy(blk.Payload, msg[off:])

		b, err := blk.ToBytes()
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, b)

		off += sz
		remaining -= sz
		blkID++
	}

	return blocks, nil
}

func encryptBlock(b []byte, sender *ecdh.PrivateKey, recipient *ecdh.PublicKey) ([]byte, error) {
	if len(b) != blockLength {
		return nil, fmt.Errorf("block: invalid plaintext length: %v (Expecting %v)", len(b), blockLength)
	}

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	senderDH := noise.DHKey{
		Private: sender.Bytes(),
		Public:  sender.PublicKey().Bytes(),
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeX,
		Initiator:     true,
		StaticKeypair: senderDH,
		PeerStatic:    recipient.Bytes(),
	})
	if err != nil {
		return nil, err
	}
	ciphertext, _, _, err := hs.WriteMessage(nil, b)
	return ciphertext, err
}

// EncryptMessage encrypts a message after fragmenting it into blocks, and
// returns a vector of byte serialized ciphertexts.
func EncryptMessage(msgID *[MessageIDLength]byte, msg []byte, sender *ecdh.PrivateKey, recipient *ecdh.PublicKey) ([][]byte, error) {
	ptVec, err := bytesVectorFromMessage(msgID, msg)
	if err != nil {
		return nil, err
	}

	ctVec := make([][]byte, 0, len(ptVec))
	for _, pt := range ptVec {
		ct, err := encryptBlock(pt, sender, recipient)
		if err != nil {
			return nil, err
		}
		ctVec = append(ctVec, ct)
	}

	return ctVec, nil
}

// DecryptBlock authenticates and decrypts a encrypted Block, and returns the
// Block and sender's static PublicKey.
func DecryptBlock(b []byte, recipient *ecdh.PrivateKey) (*Block, *ecdh.PublicKey, error) {
	if len(b) != BlockCiphertextLength {
		return nil, nil, fmt.Errorf("block: invalid ciphertext length: %v (Expecting %v)", len(b), BlockCiphertextLength)
	}

	// Decrypt the ciphertext into a plaintext.
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	recipientDH := noise.DHKey{
		Private: recipient.Bytes(),
		Public:  recipient.PublicKey().Bytes(),
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
		return nil, nil, err
	}
	plaintext, _, _, err := hs.ReadMessage(nil, b)
	if err != nil {
		return nil, nil, err
	}

	// Save the sender's static public key.
	senderPk := new(ecdh.PublicKey)
	if err = senderPk.FromBytes(hs.PeerStatic()); err != nil {
		panic("BUG: block: Failed to de-serialize peer static key: " + err.Error())
	}

	// Parse the plaintext into a Block.
	blk := new(Block)
	err = blk.FromBytes(plaintext)

	return blk, senderPk, err
}
