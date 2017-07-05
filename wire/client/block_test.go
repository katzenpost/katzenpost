// block_test.go - Noise based wire protocol client tests.
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

package client

import (
	"crypto/rand"
	"testing"

	"github.com/katzenpost/noise"
	"github.com/stretchr/testify/assert"
)

func TestBlockToBytesFromBytes(t *testing.T) {
	assert := assert.New(t)

	block1 := Block{}
	copy(block1.messageId[:], []byte(string("message id")))
	block1.totalBlocks = uint16(3)
	block1.blockId = uint16(96)
	copy(block1.block, []byte(string("zomg bbq wtf lol")))
	raw1 := block1.toBytes()
	block2 := FromBytes(raw1)
	raw2 := block2.toBytes()

	assert.Equal(raw1, raw2, "byte slices should be equal")
}

func TestBlockEncryptDecrypt(t *testing.T) {
	assert := assert.New(t)

	ciphersuite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
	static1 := ciphersuite.GenerateKeypair(rand.Reader)
	var static1PubKey, static1PrivKey [32]byte
	copy(static1PubKey[:], static1.Public)
	copy(static1PrivKey[:], static1.Private)
	client1 := NewBlockClient(&static1PubKey, &static1PrivKey, rand.Reader)

	static2 := ciphersuite.GenerateKeypair(rand.Reader)
	var static2PubKey, static2PrivKey [32]byte
	copy(static2PubKey[:], static2.Public)
	copy(static2PrivKey[:], static2.Private)
	client2 := NewBlockClient(&static2PubKey, &static2PrivKey, rand.Reader)

	block1 := Block{}
	copy(block1.messageId[:], []byte(string("message id")))
	block1.totalBlocks = uint16(3)
	block1.blockId = uint16(96)
	copy(block1.block, []byte(string("zomg bbq wtf lol")))

	ciphertext1 := client1.EncryptBlock(static2PubKey, &block1)

	block2, err := client2.DecryptBlock(ciphertext1)
	assert.NoError(err, "error not expected")

	raw1 := block1.toBytes()
	raw2 := block2.toBytes()
	assert.Equal(raw1, raw2, "byte slices should be equal")
}
