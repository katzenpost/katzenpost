// SPDX-License-Identifier: AGPL-3.0-only

package commands

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

// rawCommandFrame builds a wire command frame (header + body) with the length
// field set to exactly len(body) and no trailing padding, so FromBytes reaches
// the per-command deserializer with the crafted body.
func rawCommandFrame(id commandID, body []byte) []byte {
	frame := make([]byte, cmdOverhead+len(body))
	frame[0] = byte(id)
	binary.BigEndian.PutUint32(frame[2:6], uint32(len(body)))
	copy(frame[cmdOverhead:], body)
	return frame
}

func testMixnetCommands(t *testing.T) *Commands {
	t.Helper()
	nike := schemes.ByName("x25519")
	g := geo.GeometryFromUserForwardPayloadLength(nike, 123, true, 5)
	return NewMixnetCommands(sphinx.NewSphinx(g).Geometry())
}

// TestConsensus2ShortBodyRejected exercises C1: consensus2 bodies of length
// 1..8 must be rejected with errInvalidCommand rather than panicking on the
// b[1:5]/b[5:9] reads.
func TestConsensus2ShortBodyRejected(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	cmds := testMixnetCommands(t)

	for bodyLen := 0; bodyLen < consensus2BaseLength; bodyLen++ {
		body := make([]byte, bodyLen)
		frame := rawCommandFrame(consensus2, body)

		var (
			cmd Command
			err error
		)
		require.NotPanics(func() { cmd, err = cmds.FromBytes(frame) },
			"consensus2 body length %d must not panic", bodyLen)
		require.Nil(cmd, "consensus2 body length %d", bodyLen)
		require.ErrorIs(err, errInvalidCommand, "consensus2 body length %d", bodyLen)
	}

	body := make([]byte, consensus2BaseLength)
	_, err := rand.Reader.Read(body)
	require.NoError(err)
	cmd, err := cmds.FromBytes(rawCommandFrame(consensus2, body))
	require.NoError(err)
	require.IsType(&Consensus2{}, cmd)
}

func TestGetConsensus2ShortBodyRejected(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	cmds := testMixnetCommands(t)

	for bodyLen := 0; bodyLen < getConsensusLength; bodyLen++ {
		body := make([]byte, bodyLen)
		frame := rawCommandFrame(getConsensus2, body)

		var (
			cmd Command
			err error
		)
		require.NotPanics(func() { cmd, err = cmds.FromBytes(frame) },
			"get_consensus2 body length %d must not panic", bodyLen)
		require.Nil(cmd, "get_consensus2 body length %d", bodyLen)
		require.ErrorIs(err, errInvalidCommand, "get_consensus2 body length %d", bodyLen)
	}

	body := make([]byte, getConsensusLength)
	_, err := rand.Reader.Read(body)
	require.NoError(err)
	cmd, err := cmds.FromBytes(rawCommandFrame(getConsensus2, body))
	require.NoError(err)
	require.IsType(&GetConsensus2{}, cmd)
}

// TestSendRetrievePacketReplyShortBodyRejected exercises C2: a
// sendRetrievePacketReply body shorter than SURBIDLength (including the
// cmdLen==0 fall-through) must be rejected rather than panicking on b[:16].
func TestSendRetrievePacketReplyShortBodyRejected(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	cmds := testMixnetCommands(t)

	for _, bodyLen := range []int{0, 1, 10, 15} {
		body := make([]byte, bodyLen)
		frame := rawCommandFrame(sendRetrievePacketReply, body)

		var (
			cmd Command
			err error
		)
		require.NotPanics(func() { cmd, err = cmds.FromBytes(frame) },
			"sendRetrievePacketReply body length %d must not panic", bodyLen)
		require.Nil(cmd, "sendRetrievePacketReply body length %d", bodyLen)
		require.ErrorIs(err, errInvalidCommand, "sendRetrievePacketReply body length %d", bodyLen)
	}
}
