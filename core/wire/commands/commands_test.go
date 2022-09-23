// commands_test.go - Tests for wire protocol commands.
// Copyright (C) 2017  David Anthony Stainton, Yawning Angel
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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/crypto/cert"
	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/sphinx"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

func TestNoOp(t *testing.T) {
	require := require.New(t)

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := sphinx.GeometryFromForwardPayloadLength(nike, forwardPayloadLength, nrHops)
	s := sphinx.NewSphinx(nike, geo)
	cmds := &Commands{
		geo: s.Geometry(),
	}

	cmd := &NoOp{}
	b := cmd.ToBytes()
	require.Equal(cmdOverhead, len(b), "NoOp: ToBytes() length")

	c, err := cmds.FromBytes(b)
	require.NoError(err, "NoOp: FromBytes() failed")
	require.IsType(cmd, c, "NoOp: FromBytes() invalid type")
}

func TestDisconnect(t *testing.T) {
	require := require.New(t)

	cmd := &Disconnect{}
	b := cmd.ToBytes()
	require.Equal(cmdOverhead, len(b), "Disconnect: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := sphinx.GeometryFromForwardPayloadLength(nike, forwardPayloadLength, nrHops)
	s := sphinx.NewSphinx(nike, geo)
	cmds := &Commands{
		geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "Disconnect: FromBytes() failed")
	require.IsType(cmd, c, "Disconnect: FromBytes() invalid type")
}

func TestSendPacket(t *testing.T) {
	const payload = "A free man must be able to endure it when his fellow men act and live otherwise than he considers proper. He must free himself from the habit, just as soon as something does not please him, of calling for the police."

	require := require.New(t)

	cmd := &SendPacket{SphinxPacket: []byte(payload)}
	b := cmd.ToBytes()
	require.Equal(cmdOverhead+len(payload), len(b), "SendPacket: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5
	geo := sphinx.GeometryFromForwardPayloadLength(nike, forwardPayloadLength, nrHops)
	s := sphinx.NewSphinx(nike, geo)
	cmds := &Commands{
		geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "SendPacket: FromBytes() failed")
	require.IsType(cmd, c, "SendPacket: FromBytes() invalid type")

	cmd = c.(*SendPacket)
	require.Equal([]byte(payload), cmd.SphinxPacket, "SendPacket: FromBytes() SphinxPacket")
}

func TestRetrieveMessage(t *testing.T) {
	const seq = 0xbeefbeef

	require := require.New(t)

	cmd := &RetrieveMessage{Sequence: seq}
	b := cmd.ToBytes()
	require.Equal(cmdOverhead+4, len(b), "RetrieveMessage: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5
	geo := sphinx.GeometryFromForwardPayloadLength(nike, forwardPayloadLength, nrHops)
	s := sphinx.NewSphinx(nike, geo)
	cmds := &Commands{
		geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "RetrieveMessage: FromBytes() failed")
	require.IsType(cmd, c, "RetrieveMessage: FromBytes() invalid type")

	cmd = c.(*RetrieveMessage)
	require.Equal(uint32(seq), cmd.Sequence, "RetrieveMessage: FromBytes() Sequence")
}

func TestMessage(t *testing.T) {

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 2000
	nrHops := 5
	geo := sphinx.GeometryFromForwardPayloadLength(nike, forwardPayloadLength, nrHops)
	cmds := &Commands{
		geo: geo,
	}

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
	require.Equal(expectedLen, len(b), "MessageEmpty: ToBytes() length")

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
	require.Equal(expectedLen, len(b), "Message: ToBytes() length")

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
	id := make([]byte, sphinxConstants.SURBIDLength)
	_, err = rand.Reader.Read(id[:])
	require.NoError(err, "MessageACK: Failed to generate ID")

	cmdMessageACK := &MessageACK{
		Geo: geo,

		QueueSizeHint: hint,
		Sequence:      seq,
		Payload:       ackPayload,
	}
	copy(cmdMessageACK.ID[:], id[:])
	b = cmdMessageACK.ToBytes()
	require.Equal(expectedLen, len(b), "MessageACK: ToBytes() length")

	c, err = cmds.FromBytes(b)
	require.NoError(err, "MessageACK: FromBytes() failed")
	require.IsType(cmdMessageACK, c, "MessageACK: FromBytes() invalid type")

	cmdMessageACK = c.(*MessageACK)
	require.Equal(uint8(hint), cmdMessageACK.QueueSizeHint, "MessageACK: FromBytes() QueueSizeHint")
	require.Equal(uint32(seq), cmdMessageACK.Sequence, "MessageACK: FromBytes() Sequence")
	require.Equal(id[:], cmdMessageACK.ID[:], "MessageACK: FromBytes() ID")
	require.Equal(ackPayload, cmdMessageACK.Payload, "MessageACK: FromBytes() Payload")
}

func TestGetConsensus(t *testing.T) {
	require := require.New(t)

	cmd := &GetConsensus{
		Epoch: 123,
	}
	b := cmd.ToBytes()
	require.Equal(getConsensusLength+cmdOverhead, len(b), "GetConsensus: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5
	geo := sphinx.GeometryFromForwardPayloadLength(nike, forwardPayloadLength, nrHops)
	s := sphinx.NewSphinx(nike, geo)
	cmds := &Commands{
		geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "GetConsensus: FromBytes() failed")
	require.IsType(cmd, c, "GetConsensus: FromBytes() invalid type")
}

func TestConsensus(t *testing.T) {
	require := require.New(t)

	cmd := &Consensus{
		Payload:   []byte("TANSTAFL: There's ain't no such thing as a free lunch."),
		ErrorCode: ConsensusOk,
	}
	b := cmd.ToBytes()
	require.Len(b, consensusBaseLength+len(cmd.Payload)+cmdOverhead, "GetConsensus: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5
	geo := sphinx.GeometryFromForwardPayloadLength(nike, forwardPayloadLength, nrHops)
	s := sphinx.NewSphinx(nike, geo)
	cmds := &Commands{
		geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "Consensus: FromBytes() failed")
	require.IsType(cmd, c, "Consensus: FromBytes() invalid type")
	d := c.(*Consensus)
	require.Equal(d.Payload, cmd.Payload)
	require.Equal(d.ErrorCode, cmd.ErrorCode)

	cmd.Payload = nil
	cmd.ErrorCode = ConsensusNotFound // Just set it to something non 0.
	b = cmd.ToBytes()
	require.Len(b, consensusBaseLength+len(cmd.Payload)+cmdOverhead, "GetConsensus: ToBytes() length")
	c, err = cmds.FromBytes(b)
	require.NoError(err, "Consensus: FromBytes() failed")
	require.IsType(cmd, c, "Consensus: FromBytes() invalid type")
	d = c.(*Consensus)
	require.Equal(d.Payload, cmd.Payload)
	require.Equal(d.ErrorCode, cmd.ErrorCode)
}

func TestPostDescriptor(t *testing.T) {
	require := require.New(t)

	cmd := &PostDescriptor{
		Epoch:   0xdeadbabecafebeef,
		Payload: []byte("This is my descriptor."),
	}
	b := cmd.ToBytes()
	require.Equal(postDescriptorLength+len(cmd.Payload)+cmdOverhead, len(b), "PostDescriptor: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := sphinx.GeometryFromForwardPayloadLength(nike, forwardPayloadLength, nrHops)
	s := sphinx.NewSphinx(nike, geo)

	cmds := &Commands{
		geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "PostDescriptor: FromBytes() failed")
	require.IsType(cmd, c, "PostDescriptor: FromBytes() invalid type")
	d := c.(*PostDescriptor)
	require.Equal(d.Epoch, cmd.Epoch)
	require.Equal(d.Payload, cmd.Payload)
}

func TestPostDescriptorStatus(t *testing.T) {
	require := require.New(t)

	cmd := &PostDescriptorStatus{
		ErrorCode: 23,
	}
	b := cmd.ToBytes()
	require.Len(b, postDescriptorStatusLength+cmdOverhead, "PostDescriptorStatus: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := sphinx.GeometryFromForwardPayloadLength(nike, forwardPayloadLength, nrHops)
	s := sphinx.NewSphinx(nike, geo)

	cmds := &Commands{
		geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "PostDescriptorStatus: FromBytes() failed")
	require.IsType(cmd, c, "PostDescriptorStatus: FromBytes() invalid type")
	d := c.(*PostDescriptorStatus)
	require.Equal(d.ErrorCode, cmd.ErrorCode)
}

func TestGetVote(t *testing.T) {
	require := require.New(t)
	_, alicePub := cert.Scheme.NewKeypair()

	cmd := &GetVote{
		Epoch:     123,
		PublicKey: alicePub,
	}
	b := cmd.ToBytes()
	require.Equal(voteOverhead+cmdOverhead, len(b), "GetVote: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := sphinx.GeometryFromForwardPayloadLength(nike, forwardPayloadLength, nrHops)
	s := sphinx.NewSphinx(nike, geo)

	cmds := &Commands{
		geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "GetVote: FromBytes() failed")
	require.IsType(cmd, c, "GetVote: FromBytes() invalid type")
}

func TestVote(t *testing.T) {
	require := require.New(t)

	_, alicePub := cert.Scheme.NewKeypair()
	cmd := &Vote{
		Epoch:     3141,
		PublicKey: alicePub,
		Payload:   []byte{1, 2, 3, 4},
	}
	b := cmd.ToBytes()
	require.Len(b, cmdOverhead+voteOverhead+len(cmd.Payload), "Vote: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := sphinx.GeometryFromForwardPayloadLength(nike, forwardPayloadLength, nrHops)
	s := sphinx.NewSphinx(nike, geo)

	cmds := &Commands{
		geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "Vote: FromBytes() failed")
	require.IsType(cmd, c, "Vote: FromBytes() invalid type")
	d := c.(*Vote)
	require.Equal(d.Epoch, cmd.Epoch)
	require.Equal(d.PublicKey.Bytes(), cmd.PublicKey.Bytes())
	require.Equal(d.Payload, cmd.Payload)
}

func TestVoteStatus(t *testing.T) {
	require := require.New(t)

	cmd := &VoteStatus{
		ErrorCode: 23,
	}
	b := cmd.ToBytes()
	require.Len(b, voteStatusLength+cmdOverhead, "VoteStatus: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := sphinx.GeometryFromForwardPayloadLength(nike, forwardPayloadLength, nrHops)
	s := sphinx.NewSphinx(nike, geo)

	cmds := &Commands{
		geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "VoteStatus: FromBytes() failed")
	require.IsType(cmd, c, "VoteStatus: FromBytes() invalid type")
	d := c.(*VoteStatus)
	require.Equal(d.ErrorCode, cmd.ErrorCode)
}

func TestReveal(t *testing.T) {
	require := require.New(t)

	_, alicePub := cert.Scheme.NewKeypair()
	digest := make([]byte, 32)
	for i := 0; i < 32; i++ {
		digest[i] = uint8(i)
	}
	cmd := &Reveal{
		Epoch:     3141,
		PublicKey: alicePub,
		Payload:   digest,
	}
	b := cmd.ToBytes()
	require.Len(b, cmdOverhead+revealOverhead+32, "Reveal: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5

	geo := sphinx.GeometryFromForwardPayloadLength(nike, forwardPayloadLength, nrHops)
	s := sphinx.NewSphinx(nike, geo)

	cmds := &Commands{
		geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "Reveal: FromBytes() failed")
	require.IsType(cmd, c, "Reveal: FromBytes() invalid type")
	d := c.(*Reveal)
	require.Equal(d.Epoch, cmd.Epoch)
	require.Equal(d.PublicKey.Bytes(), cmd.PublicKey.Bytes())
	require.Equal(d.Payload, cmd.Payload)
}

func TestRevealtatus(t *testing.T) {
	require := require.New(t)

	cmd := &RevealStatus{
		ErrorCode: 23,
	}
	b := cmd.ToBytes()
	require.Len(b, revealStatusLength+cmdOverhead, "RevealStatus: ToBytes() length")

	nike := ecdh.NewEcdhNike(rand.Reader)
	forwardPayloadLength := 123
	nrHops := 5
	geo := sphinx.GeometryFromForwardPayloadLength(nike, forwardPayloadLength, nrHops)
	s := sphinx.NewSphinx(nike, geo)
	cmds := &Commands{
		geo: s.Geometry(),
	}

	c, err := cmds.FromBytes(b)
	require.NoError(err, "RevealStatus: FromBytes() failed")
	require.IsType(cmd, c, "RevealStatus: FromBytes() invalid type")
	d := c.(*RevealStatus)
	require.Equal(d.ErrorCode, cmd.ErrorCode)
}
