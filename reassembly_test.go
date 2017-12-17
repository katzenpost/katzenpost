// reassembly_test.go - message reassembly tests
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
	"bytes"
	"testing"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/minclient/block"
	"github.com/stretchr/testify/require"
)

func TestBlockValidation(t *testing.T) {
	require := require.New(t)
	messageID := [block.MessageIDLength]byte{}
	senderPrivKey, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err, "wtf")
	senderPubKey := senderPrivKey.PublicKey()
	blocks := []*IngressBlock{
		&IngressBlock{
			SenderPubKey: senderPubKey,
			Block: &block.Block{
				MessageID:   messageID,
				TotalBlocks: 3,
				BlockID:     0,
				Payload:     []byte{1, 2, 3},
			},
		},
		&IngressBlock{
			SenderPubKey: senderPubKey,
			Block: &block.Block{
				MessageID:   messageID,
				TotalBlocks: 3,
				BlockID:     1,
				Payload:     []byte{1, 2, 3},
			},
		},
		&IngressBlock{
			SenderPubKey: senderPubKey,
			Block: &block.Block{
				MessageID:   messageID,
				TotalBlocks: 3,
				BlockID:     2,
				Payload:     []byte{1, 2, 3},
			},
		},
	}
	err = validateBlocks(blocks)
	require.NoError(err, "wtf")
}

func TestReassemblyMissingBlockID(t *testing.T) {
	require := require.New(t)
	messageID := [block.MessageIDLength]byte{}
	senderPrivKey, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err, "wtf")
	senderPubKey := senderPrivKey.PublicKey()
	blocks := []*IngressBlock{
		&IngressBlock{
			SenderPubKey: senderPubKey,
			Block: &block.Block{
				MessageID:   messageID,
				TotalBlocks: 3,
				BlockID:     0,
				Payload:     []byte{1, 2, 3},
			},
		},
		&IngressBlock{
			SenderPubKey: senderPubKey,
			Block: &block.Block{
				MessageID:   messageID,
				TotalBlocks: 3,
				BlockID:     2,
				Payload:     []byte{1, 2, 3},
			},
		},
	}
	err = validateBlocks(blocks)
	require.Error(err, "wtf")
}

func TestReassemblyMismatchMessageID(t *testing.T) {
	require := require.New(t)
	messageID1 := [block.MessageIDLength]byte{}
	messageID2 := [block.MessageIDLength]byte{}
	_, err := rand.Reader.Read(messageID2[:])
	require.NoError(err, "wtf")
	senderPrivKey, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err, "wtf")
	senderPubKey := senderPrivKey.PublicKey()

	blocks := []*IngressBlock{
		&IngressBlock{
			SenderPubKey: senderPubKey,
			Block: &block.Block{
				MessageID:   messageID1,
				TotalBlocks: 3,
				BlockID:     0,
				Payload:     []byte{1, 2, 3},
			},
		},
		&IngressBlock{
			SenderPubKey: senderPubKey,
			Block: &block.Block{
				MessageID:   messageID2,
				TotalBlocks: 3,
				BlockID:     1,
				Payload:     []byte{1, 2, 3},
			},
		},
		&IngressBlock{
			SenderPubKey: senderPubKey,
			Block: &block.Block{
				MessageID:   messageID1,
				TotalBlocks: 3,
				BlockID:     2,
				Payload:     []byte{1, 2, 3},
			},
		},
	}

	err = validateBlocks(blocks)
	require.Error(err, "wtf")
}

func TestReassemblyMismatchTotalBlocks(t *testing.T) {
	require := require.New(t)
	messageID1 := [block.MessageIDLength]byte{}
	senderPrivKey, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err, "wtf")
	senderPubKey := senderPrivKey.PublicKey()

	blocks := []*IngressBlock{
		&IngressBlock{
			SenderPubKey: senderPubKey,
			Block: &block.Block{
				MessageID:   messageID1,
				TotalBlocks: 3,
				BlockID:     0,
				Payload:     []byte{1, 2, 3},
			},
		},
		&IngressBlock{
			SenderPubKey: senderPubKey,
			Block: &block.Block{
				MessageID:   messageID1,
				TotalBlocks: 1,
				BlockID:     1,
				Payload:     []byte{1, 2, 3},
			},
		},
		&IngressBlock{
			SenderPubKey: senderPubKey,
			Block: &block.Block{
				MessageID:   messageID1,
				TotalBlocks: 3,
				BlockID:     2,
				Payload:     []byte{1, 2, 3},
			},
		},
	}

	err = validateBlocks(blocks)
	require.Error(err, "wtf")
}

func TestReassemblyMismatchSender(t *testing.T) {
	require := require.New(t)
	messageID1 := [block.MessageIDLength]byte{}
	senderPrivKey1, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err, "wtf")
	senderPubKey1 := senderPrivKey1.PublicKey()
	senderPrivKey2, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err, "wtf")
	senderPubKey2 := senderPrivKey2.PublicKey()

	blocks := []*IngressBlock{
		&IngressBlock{
			SenderPubKey: senderPubKey1,
			Block: &block.Block{
				MessageID:   messageID1,
				TotalBlocks: 3,
				BlockID:     0,
				Payload:     []byte{1, 2, 3},
			},
		},
		&IngressBlock{
			SenderPubKey: senderPubKey1,
			Block: &block.Block{
				MessageID:   messageID1,
				TotalBlocks: 3,
				BlockID:     1,
				Payload:     []byte{1, 2, 3},
			},
		},
		&IngressBlock{
			SenderPubKey: senderPubKey2,
			Block: &block.Block{
				MessageID:   messageID1,
				TotalBlocks: 3,
				BlockID:     2,
				Payload:     []byte{1, 2, 3},
			},
		},
	}

	err = validateBlocks(blocks)
	require.Error(err, "wtf")
}

func TestDeduplication1(t *testing.T) {
	require := require.New(t)

	messageID := [block.MessageIDLength]byte{}

	blocks := []*IngressBlock{
		&IngressBlock{
			Block: &block.Block{
				MessageID:   messageID,
				TotalBlocks: 3,
				BlockID:     0,
				Payload:     []byte{1, 2, 3},
			},
		},
		&IngressBlock{
			Block: &block.Block{
				MessageID:   messageID,
				TotalBlocks: 3,
				BlockID:     0,
				Payload:     []byte{1, 2, 3},
			},
		},
		&IngressBlock{
			Block: &block.Block{
				MessageID:   messageID,
				TotalBlocks: 3,
				BlockID:     2,
				Payload:     []byte{1, 2, 3},
			},
		},
	}

	deduped := deduplicateBlocks(blocks)
	require.NotEqual(len(deduped), len(blocks), "deduplicateBlocks failed")
}

func TestDeduplication2(t *testing.T) {
	require := require.New(t)

	messageID := [block.MessageIDLength]byte{}
	blocks := []*IngressBlock{
		&IngressBlock{
			Block: &block.Block{
				MessageID:   messageID,
				TotalBlocks: 3,
				BlockID:     0,
				Payload:     []byte{1, 2, 3},
			},
		},
		&IngressBlock{
			Block: &block.Block{
				MessageID:   messageID,
				TotalBlocks: 3,
				BlockID:     0,
				Payload:     []byte{1, 2, 3},
			},
		},
		&IngressBlock{
			Block: &block.Block{
				MessageID:   messageID,
				TotalBlocks: 3,
				BlockID:     2,
				Payload:     []byte{1, 2, 3},
			},
		},
		&IngressBlock{
			Block: &block.Block{
				MessageID:   messageID,
				TotalBlocks: 3,
				BlockID:     1,
				Payload:     []byte{1, 2, 3},
			},
		},
		&IngressBlock{
			Block: &block.Block{
				MessageID:   messageID,
				TotalBlocks: 3,
				BlockID:     1,
				Payload:     []byte{1, 2, 3},
			},
		},
	}

	deduped := deduplicateBlocks(blocks)
	require.Equal(len(deduped), 3, "deduplicateBlocks failed")
}

func TestReassembly(t *testing.T) {
	require := require.New(t)
	messageID := [block.MessageIDLength]byte{}
	senderPrivKey, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err, "wtf")
	senderPubKey := senderPrivKey.PublicKey()
	blocks := []*IngressBlock{
		&IngressBlock{
			SenderPubKey: senderPubKey,
			Block: &block.Block{
				MessageID:   messageID,
				TotalBlocks: 3,
				BlockID:     0,
				Payload:     []byte{1, 2, 3},
			},
		},
		&IngressBlock{
			SenderPubKey: senderPubKey,
			Block: &block.Block{
				MessageID:   messageID,
				TotalBlocks: 3,
				BlockID:     1,
				Payload:     []byte{4, 5, 6},
			},
		},
		&IngressBlock{
			SenderPubKey: senderPubKey,
			Block: &block.Block{
				MessageID:   messageID,
				TotalBlocks: 3,
				BlockID:     2,
				Payload:     []byte{7, 8, 9},
			},
		},
	}
	message, err := reassemble(blocks)
	require.NoError(err, "wtf")
	require.True(bytes.Equal(message, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}))
}

func TestReassemblyMissingBlock(t *testing.T) {
	require := require.New(t)
	messageID := [block.MessageIDLength]byte{}
	blocks := []*IngressBlock{
		&IngressBlock{
			Block: &block.Block{
				MessageID:   messageID,
				TotalBlocks: 3,
				BlockID:     0,
				Payload:     []byte{1, 2, 3},
			},
		},
		&IngressBlock{
			Block: &block.Block{
				MessageID:   messageID,
				TotalBlocks: 3,
				BlockID:     2,
				Payload:     []byte{1, 2, 3},
			},
		},
	}
	_, err := reassemble(blocks)
	require.Error(err, "wtf")
}
