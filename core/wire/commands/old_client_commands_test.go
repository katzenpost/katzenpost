package commands

import (
	"testing"

	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/util"

	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func TestSendPacket(t *testing.T) {
	t.Parallel()
	const payload = "A free man must be able to endure it when his fellow men act and live otherwise than he considers proper. He must free himself from the habit, just as soon as something does not please him, of calling for the police."

	require := require.New(t)

	nike := ecdh.Scheme(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5
	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)
	cmds := NewMixnetCommands(s.Geometry())

	packet := make([]byte, geo.PacketLength)
	copy(packet[:len(payload)], payload)
	cmd := &SendPacket{SphinxPacket: packet, Cmds: cmds}
	b := cmd.ToBytes()
	require.Len(b, cmds.MaxMessageLenClientToServer, "SendPacket: ToBytes() length")
	actualDataLength := cmdOverhead + len(payload)
	require.True(util.CtIsZero(b[actualDataLength:]), "SendPacket: ToBytes() padding must be zero")

	c, err := cmds.FromBytes(b)
	require.NoError(err, "SendPacket: FromBytes() failed")
	require.IsType(cmd, c, "SendPacket: FromBytes() invalid type")

	cmd = c.(*SendPacket)
	require.Equal([]byte(packet), cmd.SphinxPacket, "SendPacket: FromBytes() SphinxPacket")
}

func TestRetrieveMessage(t *testing.T) {
	t.Parallel()
	const seq = 0xbeefbeef

	require := require.New(t)

	nike := ecdh.Scheme(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5
	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)
	cmds := NewMixnetCommands(s.Geometry())

	cmd := &RetrieveMessage{Sequence: seq, Cmds: cmds}
	b := cmd.ToBytes()
	require.Len(b, cmds.MaxMessageLenClientToServer, "RetrieveMessage: ToBytes() length")
	actualDataLength := cmdOverhead + 4
	require.True(util.CtIsZero(b[actualDataLength:]), "RetrieveMessage: ToBytes() padding must be zero")

	c, err := cmds.FromBytes(b)
	require.NoError(err, "RetrieveMessage: FromBytes() failed")
	require.IsType(cmd, c, "RetrieveMessage: FromBytes() invalid type")

	cmd = c.(*RetrieveMessage)
	require.Equal(uint32(seq), cmd.Sequence, "RetrieveMessage: FromBytes() Sequence")
}

func TestMessage(t *testing.T) {
	t.Parallel()

	nike := ecdh.Scheme(rand.Reader)
	forwardPayloadLength := 2000
	nrHops := 5
	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	cmds := NewMixnetCommands(geo)

	const seq = 0xa5a5a5a5

	require := require.New(t)

	// Message
	msgPayload := make([]byte, cmds.geo.PayloadTagLength+cmds.geo.ForwardPayloadLength)
	_, err := rand.Reader.Read(msgPayload)
	require.NoError(err, "Message: failed to generate payload")
	id := make([]byte, constants.SURBIDLength)
	_, err = rand.Reader.Read(id[:])
	require.NoError(err, "Message: Failed to generate SURBID")

	cmdMessage := &Message{
		Geo:  geo,
		Cmds: cmds,

		Sequence: seq,
		Payload:  msgPayload,
	}
	copy(cmdMessage.SURBID[:], id[:])
	b := cmdMessage.ToBytes()
	expectedLen := cmdOverhead + messageLength() + cmds.geo.PayloadTagLength + cmds.geo.ForwardPayloadLength
	require.Len(b, cmds.MaxMessageLenServerToClient, "Message: ToBytes() length")
	require.True(util.CtIsZero(b[expectedLen:]), "Message: ToBytes() padding must be zero")

	c, err := cmds.FromBytes(b)
	require.NoError(err, "Message: FromBytes() failed")
	require.IsType(cmdMessage, c, "Message: FromBytes() invalid type")

	cmdMessage = c.(*Message)
	require.Equal(uint32(seq), cmdMessage.Sequence, "Message: FromBytes() Sequence")
	require.Equal(id[:], cmdMessage.SURBID[:], "Message: FromBytes() SURBID")
	require.Equal(msgPayload, cmdMessage.Payload, "Message: FromBytes() Payload")
}

// TestMessageDelivered pins the client-to-gateway acknowledgement that
// replaces the polled RetrieveMessage in the push-delivery model. The
// client echoes back the Sequence the gateway assigned to a pushed
// Message so the gateway can advance the head of the
// client's spool. Symmetric to RetrieveMessage in size and shape; just
// flowing in the opposite direction.
func TestMessageDelivered(t *testing.T) {
	t.Parallel()
	const seq = 0xdeadbeef

	require := require.New(t)

	nike := ecdh.Scheme(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5
	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	s := sphinx.NewSphinx(geo)
	cmds := NewMixnetCommands(s.Geometry())

	cmd := &MessageDelivered{Sequence: seq, Cmds: cmds}
	b := cmd.ToBytes()
	require.Len(b, cmds.MaxMessageLenClientToServer, "MessageDelivered: ToBytes() length")
	actualDataLength := cmdOverhead + 4
	require.True(util.CtIsZero(b[actualDataLength:]), "MessageDelivered: ToBytes() padding must be zero")

	c, err := cmds.FromBytes(b)
	require.NoError(err, "MessageDelivered: FromBytes() failed")
	require.IsType(cmd, c, "MessageDelivered: FromBytes() invalid type")

	cmd = c.(*MessageDelivered)
	require.Equal(uint32(seq), cmd.Sequence, "MessageDelivered: FromBytes() Sequence")
}
