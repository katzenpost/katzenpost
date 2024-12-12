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

	var expectedLen = cmdOverhead + cmds.messageEmptyLength()
	const (
		hint = 0x17
		seq  = 0xa5a5a5a5
	)

	require := require.New(t)

	// Generate the payload.
	payload := make([]byte, cmds.geo.ForwardPayloadLength)
	_, err := rand.Reader.Read(payload)
	require.NoError(err, "Message: failed to generate payload")

	// MessageEmpty
	cmdEmpty := &MessageEmpty{
		Cmds:     cmds,
		Sequence: seq,
	}
	b := cmdEmpty.ToBytes()
	require.Len(b, cmds.MaxMessageLenServerToClient, "MessageEmpty: ToBytes() length")
	require.True(util.CtIsZero(b[expectedLen:]), "MessageEmpty: ToBytes() padding must be zero")

	c, err := cmds.FromBytes(b)
	require.NoError(err, "MessageEmpty: FromBytes() failed")
	require.IsType(cmdEmpty, c, "MessageEmpty: FromBytes() invalid type")

	cmdEmpty = c.(*MessageEmpty)
	require.Equal(uint32(seq), cmdEmpty.Sequence, "MessageEmpty: FromBytes() Sequence")

	// Message
	msgPayload := payload[:cmds.geo.UserForwardPayloadLength]
	cmdMessage := &Message{
		Geo:  geo,
		Cmds: cmds,

		QueueSizeHint: hint,
		Sequence:      seq,
		Payload:       msgPayload,
	}
	b = cmdMessage.ToBytes()
	require.Len(b, cmds.MaxMessageLenServerToClient, "Message: ToBytes() length")
	require.True(util.CtIsZero(b[expectedLen:]), "Message: ToBytes() padding must be zero")

	c, err = cmds.FromBytes(b)
	require.NoError(err, "Message: FromBytes() failed")
	require.IsType(cmdMessage, c, "Message: FromBytes() invalid type")

	cmdMessage = c.(*Message)
	require.Equal(uint8(hint), cmdMessage.QueueSizeHint, "Message: FromBytes() QueueSizeHint")
	require.Equal(uint32(seq), cmdMessage.Sequence, "Message: FromBytes() Sequence")
	require.Equal(msgPayload, cmdMessage.Payload, "Message: FromBytes() Payload")

	// MessageACK
	ackPayload := make([]byte, cmds.geo.PayloadTagLength+cmds.geo.ForwardPayloadLength)
	_, err = rand.Reader.Read(ackPayload)
	require.NoError(err, "Message: failed to generate ACK payload")
	id := make([]byte, constants.SURBIDLength)
	_, err = rand.Reader.Read(id[:])
	require.NoError(err, "MessageACK: Failed to generate ID")

	cmdMessageACK := &MessageACK{
		Geo:  geo,
		Cmds: cmds,

		QueueSizeHint: hint,
		Sequence:      seq,
		Payload:       ackPayload,
	}
	copy(cmdMessageACK.ID[:], id[:])
	b = cmdMessageACK.ToBytes()
	require.Len(b, cmds.MaxMessageLenServerToClient, "MessageACK: ToBytes() length")
	require.True(util.CtIsZero(b[expectedLen:]), "MessageACK: ToBytes() padding must be zero")

	c, err = cmds.FromBytes(b)
	require.NoError(err, "MessageACK: FromBytes() failed")
	require.IsType(cmdMessageACK, c, "MessageACK: FromBytes() invalid type")

	cmdMessageACK = c.(*MessageACK)
	require.Equal(uint8(hint), cmdMessageACK.QueueSizeHint, "MessageACK: FromBytes() QueueSizeHint")
	require.Equal(uint32(seq), cmdMessageACK.Sequence, "MessageACK: FromBytes() Sequence")
	require.Equal(id[:], cmdMessageACK.ID[:], "MessageACK: FromBytes() ID")
	require.Equal(ackPayload, cmdMessageACK.Payload, "MessageACK: FromBytes() Payload")
}
