// session_test.go - session tests
// Copyright (C) 2017  David Stainton
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

// Package client provides the Katzenpost midclient
package client

import (
	"testing"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/minclient/block"
	"github.com/stretchr/testify/require"
)

func TestIngressBlockSerialization(t *testing.T) {
	require := require.New(t)

	messageID := [block.MessageIDLength]byte{}
	senderPrivKey, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err, "wtf")
	senderPubKey := senderPrivKey.PublicKey()
	ingressBlock := &IngressBlock{
		SenderPubKey: senderPubKey,
		Block: &block.Block{
			MessageID:   messageID,
			TotalBlocks: 3,
			BlockLength: 3,
			BlockID:     0,
			Payload:     []byte{1, 2, 3},
		},
	}

	rawBlock, err := ingressBlock.ToBytes()
	require.NoError(err, "wtf")

	newBlock := new(IngressBlock)
	err = newBlock.FromBytes(rawBlock)
	require.NoError(err, "wtf")

	rawNewBlock, err := newBlock.ToBytes()
	require.NoError(err, "wtf")
	require.Equal(rawNewBlock, rawBlock)
}
