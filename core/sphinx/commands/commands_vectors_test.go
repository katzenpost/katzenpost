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
	"encoding/json"
	"os"
	"testing"

	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/internal/crypto"
	"github.com/stretchr/testify/assert"
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
	t.Parallel()
	assert := assert.New(t)

	cmdsTest := commandsTest{
		NextHopID:        "d949152fd0e541549225baac771c65f99cbe820afad04fbdd10a4b9ec68eef8a",
		NextHopMAC:       "1f7b011fe8519cafc77b2a4c2e1e3ab9",
		NextHopCmdWant:   "01d949152fd0e541549225baac771c65f99cbe820afad04fbdd10a4b9ec68eef8a1f7b011fe8519cafc77b2a4c2e1e3ab9",
		RecipientID:      "ccaf6125a610bd298ab8a15f5e8fef72b46ca7a8db936d6b2400e2742531f80b",
		RecipientCmdWant: "02ccaf6125a610bd298ab8a15f5e8fef72b46ca7a8db936d6b2400e2742531f80b",
		SURBReplyID:      "479ed2fe89fb26e2272f2899eb0e2d2f",
		SURBReplyCmdWant: "03479ed2fe89fb26e2272f2899eb0e2d2f",
		NodeDelay:        1234,
		NodeDelayCmdWant: "80000004d2",
	}

	_, err := json.Marshal(cmdsTest)
	assert.NoError(err)

	//t.Logf("vectors in JSON:\n%s\n", string(serialized))
}

func TestCommandVectors(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	serialized, err := os.ReadFile(sphinxCommandsVectorsFile)
	assert.NoError(err)
	cmdsTest := commandsTest{}
	err = json.Unmarshal(serialized, &cmdsTest)
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
	_, err = hex.DecodeString(cmdsTest.NextHopCmdWant)
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
