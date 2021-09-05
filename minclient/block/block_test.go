// block_tests.go - End to End message block tests.
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

package block

import (
	"crypto/rand"
	"testing"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlockPlaintext(t *testing.T) {
	require := require.New(t)

	var msgID [MessageIDLength]byte
	_, err := rand.Read(msgID[:])
	require.NoError(err, "rand.Read(msgID)")

	msg := make([]byte, 2*BlockPayloadLength)
	_, err = rand.Read(msg)
	require.NoError(err, "rand.Read(msg)")

	for sz := 0; sz < len(msg); sz++ {
		// Encode the message into blocks and byte serialize.
		vec, err := bytesVectorFromMessage(&msgID, msg[:sz])
		require.NoError(err, "BytesVectorFromMessage(&msgID, msg[:%v])", sz)

		// Deserialize each byte serialized block and reassemble the message.
		reassembled := make([]byte, 0, sz)
		for i, b := range vec {
			require.Len(b, blockLength, "vec[%v] (%v)", i, sz)

			var blk Block
			err = blk.FromBytes(b)
			require.NoError(err, "blk.FromBytes(vec[%v]) (%v)", i, sz)
			require.Equal(msgID, blk.MessageID, "vec[%v] (%v)", i, sz)
			require.Equal(uint16(len(vec)), blk.TotalBlocks, "vec[%v] (%v)", i, sz)
			require.Equal(uint16(i), blk.BlockID, "vec[%v] (%v)", i, sz)
			require.Equal(uint32(len(blk.Payload)), blk.BlockLength, "vec[%v] (%v)", i, sz)
			reassembled = append(reassembled, blk.Payload...)
		}
		require.Equal(msg[:sz], reassembled, "reassembled != msg[:%v]", sz)
	}
}

func TestBlockCrypto(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// Test vectors taken from the H.P. Lovecraft Historical Society's
	// Christmas songs, in the seasonal spirit.

	blkPayload := []byte(`Awake ye scary great Old Ones
Let everything dismay!
Remember great Cthulhu shall rise up from R'yleh
To kill us all with tentacles if we should go his way!

O' tidings of madness and woe, madness and woe,
O' tidings of madness and woe! (and great woe)`)
	blk := &Block{
		TotalBlocks: 1,
		BlockID:     0,
		BlockLength: uint32(len(blkPayload)),
		Payload:     blkPayload,
	}
	rand.Read(blk.MessageID[:])
	blkPlaintext, err := blk.ToBytes()
	require.NoError(err, "blk.ToBytes()")

	sender, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err, "ecdh.NewKeypair(sender)")

	recipient, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err, "ecdh.NewKeypair(recipient)")

	// Test the underlying internals first.
	ciphertext, err := encryptBlock(blkPlaintext, sender, recipient.PublicKey())
	require.NoError(err, "encryptBlock()")
	require.Len(ciphertext, BlockCiphertextLength)

	b, pk, err := DecryptBlock(ciphertext, recipient)
	require.NoError(err, "DecryptBlock()")
	assert.True(sender.PublicKey().Equal(pk), "Sender static, from DecryptBlock")
	assert.Equal(blk, b, "blk != DecryptBlock(encryptBlock(blk))")

	// "Test" the EncryptMessage interface.
	//
	// The fragmentation isn't really exercised since TestBlockPlaintext
	// exercises the internals.
	msgPlaintext := []byte(`Death to the world! Cthulhu's come.
Let Earth abhor this thing.
Let every mind prepare for doom,
As anguish and woe he'll bring. (And anguish and woe he'll bring.)
As anguish and woe he'll bring. (Anguish and woe he'll bring.)
As anguish, as anguish and woe he'll bring.`)

	ctVec, err := EncryptMessage(&blk.MessageID, msgPlaintext, sender, recipient.PublicKey())
	require.NoError(err, "EncryptMessage()")
	require.Len(ctVec, 1, "Should only be one block.")

	b, pk, err = DecryptBlock(ctVec[0], recipient)
	require.NoError(err, "DecryptBlock(ctVec[0])")
	assert.True(sender.PublicKey().Equal(pk), "Sender static, from DecryptBlock(ctVec[0])")
	assert.Equal(msgPlaintext, b.Payload, "msg != DecryptBlock(EncryptMesage(msg)")
}
