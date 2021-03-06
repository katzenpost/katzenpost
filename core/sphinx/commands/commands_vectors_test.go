// commands_test.go - Per-hop Routing Info Commands vector tests.
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

package commands

import (
	"encoding/hex"
	"io/ioutil"
	"testing"

	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/ugorji/go/codec"
)

const sphinxCommandsVectorsFile = "testdata/sphinx_commands_vectors.json"

type commandsTest struct {
	NextHopID        string
	NextHopMAC       string
	NextHopCmdWant   string
	RecipientID      string
	RecipientCmdWant string
	SURBReplyID      string
	SURBReplyCmdWant string
	NodeDelay        uint32
	NodeDelayCmdWant string
}

func TestBuildCommandVectors(t *testing.T) {
	assert := assert.New(t)

	cmdsTest := commandsTest{
		NextHopID:        "d949152fd0e541549225baac771c65f99cbe820afad04fbdd10a4b9ec68eef8a",
		NextHopMAC:       "1f7b011fe8519cafc77b2a4c2e1e3ab9",
		NextHopCmdWant:   "01d949152fd0e541549225baac771c65f99cbe820afad04fbdd10a4b9ec68eef8a1f7b011fe8519cafc77b2a4c2e1e3ab9",
		RecipientID:      "52b0f869d0d49d8eb43e9efec1fb70a093212f0ddd4512471dc4edbf2fc85e31292b0f08a87195deaf57d59a17567da4848e3a0a08bfa6a42c49430d0f3b1e0a",
		RecipientCmdWant: "0252b0f869d0d49d8eb43e9efec1fb70a093212f0ddd4512471dc4edbf2fc85e31292b0f08a87195deaf57d59a17567da4848e3a0a08bfa6a42c49430d0f3b1e0a",
		SURBReplyID:      "479ed2fe89fb26e2272f2899eb0e2d2f",
		SURBReplyCmdWant: "03479ed2fe89fb26e2272f2899eb0e2d2f",
		NodeDelay:        1234,
		NodeDelayCmdWant: "80000004d2",
	}

	serialized := []byte{}
	handle := new(codec.JsonHandle)
	handle.Indent = 4
	enc := codec.NewEncoderBytes(&serialized, handle)
	err := enc.Encode(cmdsTest)
	assert.NoError(err)
	//t.Logf("vectors in JSON:\n%s\n", string(serialized))
}

func TestCommandVectors(t *testing.T) {
	assert := assert.New(t)

	serialized, err := ioutil.ReadFile(sphinxCommandsVectorsFile)
	assert.NoError(err)
	decoder := codec.NewDecoderBytes(serialized, new(codec.JsonHandle))
	cmdsTest := commandsTest{}
	err = decoder.Decode(&cmdsTest)
	assert.NoError(err)

	// NextHop command
	nextHopID, err := hex.DecodeString(cmdsTest.NextHopID)
	assert.NoError(err)
	nextHopMAC, err := hex.DecodeString(cmdsTest.NextHopMAC)
	assert.NoError(err)
	id := [constants.NodeIDLength]byte{}
	copy(id[:], nextHopID)
	mac := [crypto.MACLength]byte{}
	copy(mac[:], nextHopMAC)
	nextHopCmd := NextNodeHop{
		ID:  id,
		MAC: mac,
	}
	nextHop := nextHopCmd.ToBytes([]byte{})
	nextHopCmdWant, err := hex.DecodeString(cmdsTest.NextHopCmdWant)
	assert.NoError(err)
	assert.Equal(nextHopCmdWant, nextHop)

	// Recipient command
	recipientID, err := hex.DecodeString(cmdsTest.RecipientID)
	assert.NoError(err)
	recipient := Recipient{}
	copy(recipient.ID[:], recipientID)
	recipientCmdWant, err := hex.DecodeString(cmdsTest.RecipientCmdWant)
	assert.NoError(err)
	assert.Equal(recipientCmdWant, recipient.ToBytes([]byte{}))

	// SURBReply command
	surbReplyID, err := hex.DecodeString(cmdsTest.SURBReplyID)
	assert.NoError(err)
	surbReply := SURBReply{}
	copy(surbReply.ID[:], surbReplyID)
	surbReplyCmdWant, err := hex.DecodeString(cmdsTest.SURBReplyCmdWant)
	assert.NoError(err)
	assert.Equal(surbReplyCmdWant, surbReply.ToBytes([]byte{}))

	// NodeDelay command
	nodeDelay := NodeDelay{
		Delay: cmdsTest.NodeDelay,
	}
	nodeDelayCmdWant, err := hex.DecodeString(cmdsTest.NodeDelayCmdWant)
	assert.NoError(err)
	assert.Equal(nodeDelayCmdWant, nodeDelay.ToBytes([]byte{}))
}
