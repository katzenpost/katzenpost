// reassembly.go - message reassembly
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
	"errors"
	"sort"
)

// deduplicateBlocks deduplicates the given blocks according to the BlockIDs
func deduplicateBlocks(blocks []*IngressBlock) []*IngressBlock {
	blockIDMap := make(map[uint16]bool)
	deduped := []*IngressBlock{}
	for _, b := range blocks {
		_, ok := blockIDMap[b.Block.BlockID]
		if !ok {
			blockIDMap[b.Block.BlockID] = true
			deduped = append(deduped, b)
		}
	}
	return deduped
}

// validateBlocks returns an error if the set
// of blocks isn't suitable for message reassembly
func validateBlocks(blocks []*IngressBlock) error {
	messageID := blocks[0].Block.MessageID
	totalBlocks := blocks[0].Block.TotalBlocks
	senderPubKey := blocks[0].SenderPubKey
	if totalBlocks != uint16(len(blocks)) {
		return errors.New("validateBlocks failure: not enough blocks")
	}
	for _, b := range blocks {
		if !bytes.Equal(messageID[:], b.Block.MessageID[:]) {
			return errors.New("validateBlocks failure: messageID mismatch")
		}
		if totalBlocks != b.Block.TotalBlocks {
			return errors.New("validateBlocks failure: TotalBlocks field mismatch")
		}
		if !senderPubKey.Equal(b.SenderPubKey) {
			return errors.New("validateBlocks failure: sender public key mismatch")
		}
	}
	return nil
}

// ByBlockID implements sort.Interface for []*block.Block
type ByBlockID []*IngressBlock

func (a ByBlockID) Len() int           { return len(a) }
func (a ByBlockID) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByBlockID) Less(i, j int) bool { return a[i].Block.BlockID < a[j].Block.BlockID }

func reassemble(blocks []*IngressBlock) ([]byte, error) {
	deduped := deduplicateBlocks(blocks)
	err := validateBlocks(deduped)
	if err != nil {
		return nil, err
	}
	sort.Sort(ByBlockID(blocks))
	message := []byte{}
	for i, b := range blocks {
		if blocks[i].Block.BlockID != uint16(i) {
			return nil, errors.New("message reassembler failed: missing message block")
		}
		message = append(message, b.Block.Payload...)
	}
	return message, nil
}
