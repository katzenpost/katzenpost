// commands_test.go - Per-hop Routing Info Commands tests.
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

package commands

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fillRand(require *require.Assertions, b []byte) {
	_, err := rand.Read(b)
	require.NoError(err, "failed to randomize buffer")
}

func toBytesTest(assert *assert.Assertions, b []byte, sz int, id commandID, values [][]byte) {
	assert.EqualValuesf(id, b[0], "(%d).ToBytes(): Invalid command", id)
	ptr := b[1:]
	for i, v := range values {
		l := len(v)
		assert.Equalf(v, ptr[:l], "(%d).ToBytes(): Field mismatch: %d", id, i)
		ptr = ptr[l:]
	}
	assert.Equalf(sz, len(b)-len(ptr), "(%d).ToBytes(): Invalid length", id)
}

func fromBytesTest(assert *assert.Assertions, b []byte, sz int, expected RoutingCommand) []byte {
	iCmd, rest, err := FromBytes(b)
	assert.NoError(err, "FromBytes() failed")
	assert.Equal(len(rest), len(b)-sz, "FromBytes(): Returned unexpected sized rest")
	assert.EqualValues(expected, iCmd, "FromBytes(): Returned unexpected command")
	return rest
}

func fromBytesErrorTest(assert *assert.Assertions, b []byte, s string) {
	iCmd, rest, err := FromBytes(b)
	assert.Nil(iCmd, "FromBytes(): Returned cmd for "+s)
	assert.Nil(rest, "FromBytes(): Returned rest for "+s)
	assert.Error(err, "FromBytes(): Returned success for "+s)
}

func TestCommands(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// Tollerate 0 length input.
	var b []byte
	iCmd, rest, err := FromBytes(b)
	assert.Nil(iCmd, "FromBytes(): Returned cmd for null")
	assert.Nil(rest, "FromBytes(): Returned rest for null")
	assert.NoError(err, "FromBytes(): null command failed")

	// Test all the serialization routines.
	off := 0

	// NextNodeHop
	nextNodeHopCmd := &NextNodeHop{}
	fillRand(require, nextNodeHopCmd.ID[:])
	fillRand(require, nextNodeHopCmd.MAC[:])
	nextNodeHopValues := [][]byte{nextNodeHopCmd.ID[:], nextNodeHopCmd.MAC[:]}
	b = nextNodeHopCmd.ToBytes(b)
	ser := b[off:]
	off = len(b)
	toBytesTest(assert, ser, NextNodeHopLength, nextNodeHop, nextNodeHopValues)

	// Recipient
	recipientCmd := &Recipient{}
	fillRand(require, recipientCmd.ID[:])
	recipientValues := [][]byte{recipientCmd.ID[:]}
	b = recipientCmd.ToBytes(b)
	ser = b[off:]
	off = len(b)
	toBytesTest(assert, ser, RecipientLength, recipient, recipientValues)

	// SURBReply
	surbReplyCmd := &SURBReply{}
	fillRand(require, surbReplyCmd.ID[:])
	surbReplyValues := [][]byte{surbReplyCmd.ID[:]}
	b = surbReplyCmd.ToBytes(b)
	ser = b[off:]
	off = len(b)
	toBytesTest(assert, ser, SURBReplyLength, surbReply, surbReplyValues)

	// NodeDelay
	const testDelay = 0xdeadbabe
	nodeDelayCmd := &NodeDelay{}
	nodeDelayCmd.Delay = testDelay
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], nodeDelayCmd.Delay)
	nodeDelayValues := [][]byte{tmp[:]}
	b = nodeDelayCmd.ToBytes(b)
	ser = b[off:]
	toBytesTest(assert, ser, NodeDelayLength, nodeDelay, nodeDelayValues)

	// Null (No command or serialization because it is just 0x00s).
	b = append(b, []byte{0x00, 0x00, 0x00}...) // Append a null command.

	// Test the rest of the FromBytes() cases.
	b = fromBytesTest(assert, b, NextNodeHopLength, nextNodeHopCmd)
	b = fromBytesTest(assert, b, RecipientLength, recipientCmd)
	b = fromBytesTest(assert, b, SURBReplyLength, surbReplyCmd)
	b = fromBytesTest(assert, b, NodeDelayLength, nodeDelayCmd)

	// Ensure that Null commands as a terminal works as intended.
	iCmd, rest, err = FromBytes(b)
	assert.Nil(iCmd, "FromBytes(): Returned cmd instead of a null command")
	assert.Nil(rest, "FromBytes(): Returned rest after a null command")
	assert.NoError(err, "FromBytes(): Returned error for a null command")

	// Ensure that Null commands are validated.
	b = []byte{0x00, 0x00, 0x01}
	fromBytesErrorTest(assert, b, "a invalid null command")

	// Ensure that unknown commands are rejected.
	b = []byte{0xff, 0x00, 0x00}
	fromBytesErrorTest(assert, b, "a unknown command")

	// TODO: Test that truncated commands are rejected.
}
